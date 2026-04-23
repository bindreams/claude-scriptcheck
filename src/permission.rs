use crate::filter::{
    Arg0Pattern, BashFilter, BashFilterItem, EditFilter, ReadFilter, RuleSet, Verdict, WriteFilter,
};
use crate::permission_mode::PermissionMode;
use crate::settings::{self, Permissions};

/// Context needed to parse a single rule:
/// - `home` for `~/` tilde expansion in file-access rules (and Bash arg0 paths).
/// - `cwd` and `project_root` for the 4-tier path resolution applied to Bash
///   rules whose first token contains a path separator.
pub struct ParseCtx<'a> {
    pub home: &'a str,
    pub cwd: &'a str,
    pub project_root: &'a str,
}

/// Pre-parsed permission rules, separated by kind.
///
/// Each kind holds a `RuleSet<F>` with three buckets (`allow`, `deny`, `ask`).
/// The verdict is orthogonal to the filter — it's decided by which JSON array
/// in `permissions` the rule was parsed from.
#[derive(Default, Debug)]
pub struct ParsedPermissions {
    pub bash: RuleSet<BashFilter>,
    pub read: RuleSet<ReadFilter>,
    pub write: RuleSet<WriteFilter>,
    pub edit: RuleSet<EditFilter>,
}

/// Result of parsing one rule string (e.g. `"Bash(git status *)"`).
pub enum ParsedFilter {
    Bash(BashFilter),
    Read(ReadFilter),
    Write(WriteFilter),
    Edit(EditFilter),
}

pub fn parse_rules(perms: &Permissions, cwd: &str, project_root: &str) -> ParsedPermissions {
    let home = crate::env_hooks::hook_home()
        .map(|h| crate::path_util::normalize_separators(&h.to_string_lossy()))
        .unwrap_or_default();
    let ctx = ParseCtx {
        home: &home,
        cwd,
        project_root,
    };

    let mut parsed = ParsedPermissions::default();

    for rule_str in &perms.allow {
        push_parsed(&mut parsed, Verdict::Allow, rule_str, &ctx);
    }
    for rule_str in &perms.deny {
        push_parsed(&mut parsed, Verdict::Deny, rule_str, &ctx);
    }
    for rule_str in &perms.ask {
        push_parsed(&mut parsed, Verdict::Ask, rule_str, &ctx);
    }

    parsed
}

fn push_parsed(
    parsed: &mut ParsedPermissions,
    verdict: Verdict,
    rule_str: &str,
    ctx: &ParseCtx,
) {
    match parse_single_rule(rule_str, ctx) {
        Some(ParsedFilter::Bash(f)) => parsed.bash.push(verdict, f),
        Some(ParsedFilter::Read(f)) => parsed.read.push(verdict, f),
        Some(ParsedFilter::Write(f)) => parsed.write.push(verdict, f),
        Some(ParsedFilter::Edit(f)) => parsed.edit.push(verdict, f),
        None => {}
    }
}

/// Parse one rule string into a `ParsedFilter`.
///
/// Returns `None` if the rule is malformed, unrecognized (e.g. `WebSearch`), or
/// explicitly skipped (`readonly`). Malformed-input handling is silent-drop —
/// same as the pre-refactor behavior.
pub fn parse_single_rule(rule: &str, ctx: &ParseCtx) -> Option<ParsedFilter> {
    // Bare tool-level wildcards (no parentheses)
    match rule {
        "Bash" => {
            return Some(ParsedFilter::Bash(BashFilter::from_items(vec![
                BashFilterItem::MatchZeroOrMore,
            ])))
        }
        "Read" => return Some(ParsedFilter::Read(ReadFilter::new("**".to_string()))),
        "Write" => return Some(ParsedFilter::Write(WriteFilter::new("**".to_string()))),
        "Edit" => return Some(ParsedFilter::Edit(EditFilter::new("**".to_string()))),
        _ => {}
    }

    if let Some(inner) = rule.strip_prefix("Bash(").and_then(|s| s.strip_suffix(')')) {
        return parse_bash_rule(inner, ctx).map(ParsedFilter::Bash);
    }

    if let Some(inner) = rule.strip_prefix("Read(").and_then(|s| s.strip_suffix(')')) {
        let expanded = expand_tilde_or_warn(inner, ctx.home, rule)?;
        let pattern = crate::canonicalize::best_effort_canonicalize(&expanded);
        return Some(ParsedFilter::Read(ReadFilter::new(pattern)));
    }
    if let Some(inner) = rule
        .strip_prefix("Write(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let expanded = expand_tilde_or_warn(inner, ctx.home, rule)?;
        let pattern = crate::canonicalize::best_effort_canonicalize(&expanded);
        return Some(ParsedFilter::Write(WriteFilter::new(pattern)));
    }
    if let Some(inner) = rule.strip_prefix("Edit(").and_then(|s| s.strip_suffix(')')) {
        let expanded = expand_tilde_or_warn(inner, ctx.home, rule)?;
        let pattern = crate::canonicalize::best_effort_canonicalize(&expanded);
        return Some(ParsedFilter::Edit(EditFilter::new(pattern)));
    }
    None
}

/// Parse a `Bash(<inner>)` rule into a `BashFilter` by tokenizing and
/// classifying each token. See CLAUDE.md "Conventions" for the full
/// semantics; this function encodes:
///
/// - Colon-wildcard normalization on the last token (`cmd:*` → `cmd *`).
/// - `*` / `**` alone → `[MatchZeroOrMore]`.
/// - `*` at position 0 → `MatchOne`; at last position → `MatchZeroOrMore`;
///   elsewhere → `MatchOne`.
/// - `**` in any position → `MatchZeroOrMore`.
/// - Position 0 otherwise → `Arg0(Name | Path)` based on whether the token
///   contains a path separator. Path tokens are run through the 4-tier
///   resolution scheme and then canonicalized.
/// - A first-token that resolves to basename `readonly` (bare or
///   path-qualified) drops the rule entirely.
fn parse_bash_rule(inner: &str, ctx: &ParseCtx) -> Option<BashFilter> {
    let mut tokens: Vec<String> = inner.split_whitespace().map(String::from).collect();

    // Normalize Claude Code's colon-wildcard format: `cmd:*` → `cmd` + `*`.
    if let Some(last) = tokens.last() {
        if let Some(stem) = last.strip_suffix(":*") {
            let i = tokens.len() - 1;
            if stem.is_empty() {
                tokens[i] = "*".to_string();
            } else {
                tokens[i] = stem.to_string();
                tokens.push("*".to_string());
            }
        }
    }

    if tokens.is_empty() {
        return None;
    }

    let last_idx = tokens.len() - 1;
    let mut items: Vec<BashFilterItem> = Vec::with_capacity(tokens.len());
    let mut first = true;

    for (i, tok) in tokens.iter().enumerate() {
        let item = if tok == "**" {
            BashFilterItem::MatchZeroOrMore
        } else if tok == "*" {
            // Trailing `*` is MatchZeroOrMore (the familiar `Bash(foo *)` shape);
            // elsewhere it's MatchOne. In isolation (`Bash(*)`, as sole token),
            // `i == last_idx == 0` so it becomes MatchZeroOrMore — the universal
            // wildcard form.
            if i == last_idx {
                BashFilterItem::MatchZeroOrMore
            } else {
                BashFilterItem::MatchOne
            }
        } else if first {
            // Position 0 concrete token → Arg0(Name | Path).
            let pat = classify_arg0(tok, ctx)?;
            // Readonly drop: symmetric across path-qualified forms so
            // `Bash(/bin/readonly)` is dropped like bare `Bash(readonly)`.
            let basename = match &pat {
                Arg0Pattern::Name(n) => n.as_str(),
                Arg0Pattern::Path(p) => basename_of_path(p),
            };
            if basename == "readonly" {
                return None;
            }
            BashFilterItem::Arg0(pat)
        } else {
            BashFilterItem::Arg(tok.clone())
        };
        items.push(item);
        first = false;
    }

    Some(BashFilter::from_items(items))
}

/// Classify a Bash rule's arg0 token into a name-match or path-match pattern.
///
/// Returns `None` when the token is a tilde-rooted path (`~/…`) and the home
/// directory is unknown — mirrors the B3 behavior for Read/Write/Edit tilde
/// rules.
fn classify_arg0(token: &str, ctx: &ParseCtx) -> Option<Arg0Pattern> {
    if !token.contains('/') && !token.contains('\\') {
        // PATHEXT stripping is skipped for glob tokens so the user's intent
        // (e.g. `py*.exe`) isn't silently rewritten.
        let stripped = if token.contains('*') {
            token.to_string()
        } else {
            crate::path_util::strip_pathext_suffix(token).to_string()
        };
        return Some(Arg0Pattern::Name(stripped));
    }

    let resolved = settings::resolve_rule_path(token, ctx.cwd, ctx.project_root);
    // `~/…` rules go through `expand_tilde_or_warn`, which warns and returns
    // `None` when home is unknown. We carry the full `Bash(...)` string into
    // the warning for parity with Read/Write/Edit.
    let synthetic_rule = format!("Bash({token})");
    let expanded = expand_tilde_or_warn(&resolved, ctx.home, &synthetic_rule)?;
    let canonical = crate::canonicalize::best_effort_canonicalize(&expanded);
    Some(Arg0Pattern::Path(canonical))
}

fn basename_of_path(path: &str) -> &str {
    match path.rfind('/').or_else(|| path.rfind('\\')) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Wrap `expand_tilde`: when the input is tilde-rooted but home is unknown,
/// warn to stderr and return `None` so the caller drops the rule. Otherwise
/// return the expanded path.
///
/// The `rule` argument is the full rule string for the warning message. The
/// warning is emitted at most once per process to avoid spamming stderr when
/// a settings file contains many tilde rules (one line per rule per hook call
/// would be unreadable).
fn expand_tilde_or_warn(inner: &str, home: &str, rule: &str) -> Option<String> {
    match expand_tilde(inner, home) {
        Some(s) => Some(s),
        None => {
            use std::sync::OnceLock;
            static WARNED: OnceLock<()> = OnceLock::new();
            if WARNED.set(()).is_ok() {
                eprintln!(
                    "scriptcheck: dropping tilde-rooted rule (first offender: `{rule}`): \
                     home directory unknown, cannot expand `~`. Further occurrences suppressed."
                );
            }
            None
        }
    }
}

/// Load settings from disk and parse them into `ParsedPermissions`, injecting
/// synthetic allow rules for the current permission mode (currently only
/// `AcceptEdits`).
///
/// Shared between the hook dispatch path (`main.rs`) and the `cli::check` dry
/// run so both produce identical decisions for the same input.
pub fn load_perms(
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) -> ParsedPermissions {
    let loaded = settings::load_settings(cwd, project_root);
    let mut parsed = parse_rules(&loaded.permissions, cwd, project_root);

    if permission_mode == Some(PermissionMode::AcceptEdits) {
        let mut workspace_dirs = vec![project_root.to_string()];
        for dir in loaded.permissions.additional_directories {
            // TODO: see plan how-are-file-filters-expressive-newell.md § deferred items (B6)
            // The 4-tier prefix scheme (`//abs`, `~/home`, `/project-root`, cwd-relative)
            // is applied to Read/Write/Edit rule strings but not here. Claude Code's own
            // behavior for additionalDirectories paths is undocumented.
            let normalized = crate::path_util::normalize_separators(&dir);
            if normalized.starts_with('~')
                || normalized.starts_with('/')
                || crate::path_util::is_absolute(&normalized)
            {
                workspace_dirs.push(normalized);
            } else {
                workspace_dirs.push(format!("{project_root}/{normalized}"));
            }
        }
        inject_accept_edits_rules(&mut parsed, &workspace_dirs);
    }

    parsed
}

/// Inject ephemeral allow rules for `acceptEdits` mode.
/// Each workspace directory gets `Write(dir/**)` and `Edit(dir/**)` allow rules,
/// parsed through the standard `parse_single_rule` pipeline.
pub fn inject_accept_edits_rules(perms: &mut ParsedPermissions, workspace_dirs: &[String]) {
    let home = crate::env_hooks::hook_home()
        .map(|h| crate::path_util::normalize_separators(&h.to_string_lossy()))
        .unwrap_or_default();
    // Synthetic Write/Edit rules have pre-resolved absolute paths, so cwd and
    // project_root are irrelevant — pass empty strings for the ParseCtx.
    let ctx = ParseCtx {
        home: &home,
        cwd: "",
        project_root: "",
    };

    for dir in workspace_dirs {
        // Skip filesystem roots: Write(<root>/**) would auto-allow the entire
        // filesystem (or drive / UNC share). B7 — see CLAUDE.md conventions.
        if crate::path_util::is_filesystem_root(dir) {
            continue;
        }
        let normalized = crate::path_util::normalize_separators(dir);
        let base = normalized.trim_end_matches('/');
        if base.is_empty() {
            continue;
        }

        let write_rule = format!("Write({base}/**)");
        let edit_rule = format!("Edit({base}/**)");

        // `parse_single_rule` can only legitimately return `None` here if `base`
        // is tilde-rooted and home is unknown (B3 drop). Filesystem-root bases
        // are already filtered by `is_filesystem_root`, and the rule shape is
        // always well-formed by construction, so any other `None` is a bug.
        if let Some(ParsedFilter::Write(f)) = parse_single_rule(&write_rule, &ctx) {
            perms.write.allow.push(f);
        }
        if let Some(ParsedFilter::Edit(f)) = parse_single_rule(&edit_rule, &ctx) {
            perms.edit.allow.push(f);
        }
    }
}

/// Expand a leading `~/` or bare `~` to the home directory.
/// Does NOT expand `~` in the middle of a path (e.g. `/home/user/my~project`).
///
/// Returns `None` when `home` is empty AND the path is tilde-rooted — the
/// caller should drop the rule rather than silently keep a literal `~` that
/// would never match a real path (B3).
fn expand_tilde(path: &str, home: &str) -> Option<String> {
    if home.is_empty() {
        if path.starts_with('~') {
            return None;
        }
        return Some(path.to_string());
    }
    if let Some(rest) = path.strip_prefix("~/") {
        Some(format!("{home}/{rest}"))
    } else if path == "~" {
        Some(home.to_string())
    } else {
        Some(path.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Arg0Pattern, BashFilterItem};

    fn ctx_default() -> ParseCtx<'static> {
        ParseCtx {
            home: "",
            cwd: "",
            project_root: "",
        }
    }

    fn items_of(rule: &str, ctx: &ParseCtx) -> Vec<BashFilterItem> {
        match parse_single_rule(rule, ctx).expect("parse should succeed") {
            ParsedFilter::Bash(f) => f.items,
            _ => panic!("expected Bash filter"),
        }
    }

    fn name_item(items: &[BashFilterItem], i: usize) -> &str {
        match &items[i] {
            BashFilterItem::Arg0(Arg0Pattern::Name(s)) => s.as_str(),
            other => panic!("items[{i}]: expected Arg0::Name, got {other:?}"),
        }
    }

    fn path_item(items: &[BashFilterItem], i: usize) -> &str {
        match &items[i] {
            BashFilterItem::Arg0(Arg0Pattern::Path(p)) => p.as_str(),
            other => panic!("items[{i}]: expected Arg0::Path, got {other:?}"),
        }
    }

    fn arg_item(items: &[BashFilterItem], i: usize) -> &str {
        match &items[i] {
            BashFilterItem::Arg(s) => s.as_str(),
            other => panic!("items[{i}]: expected Arg, got {other:?}"),
        }
    }

    fn is_mzm(items: &[BashFilterItem], i: usize) -> bool {
        matches!(items.get(i), Some(BashFilterItem::MatchZeroOrMore))
    }

    fn is_one(items: &[BashFilterItem], i: usize) -> bool {
        matches!(items.get(i), Some(BashFilterItem::MatchOne))
    }

    #[test]
    fn parse_bash_bare_name() {
        let items = items_of("Bash(rg *)", &ctx_default());
        assert_eq!(items.len(), 2);
        assert_eq!(name_item(&items, 0), "rg");
        assert!(is_mzm(&items, 1));
    }

    #[test]
    fn parse_bash_pathext_stripped_at_parse() {
        let items = items_of("Bash(rg.cmd *)", &ctx_default());
        assert_eq!(name_item(&items, 0), "rg");
        assert!(is_mzm(&items, 1));
    }

    #[test]
    fn parse_bash_pathext_stripped_for_exe_and_bat() {
        assert_eq!(
            name_item(&items_of("Bash(python.exe -c *)", &ctx_default()), 0),
            "python"
        );
        assert_eq!(
            name_item(&items_of("Bash(python.bat -c *)", &ctx_default()), 0),
            "python"
        );
    }

    #[test]
    fn parse_bash_glob_name_preserves_literal_extension() {
        // PATHEXT stripping is skipped for glob rule names so the user's
        // intent to match a specific extension is preserved verbatim.
        let items = items_of("Bash(py*.exe *)", &ctx_default());
        assert_eq!(name_item(&items, 0), "py*.exe");
    }

    #[test]
    fn parse_bash_relative_path_resolved() {
        let items = items_of(
            "Bash(./tools/rg.cmd *)",
            &ParseCtx {
                home: "",
                cwd: "/project",
                project_root: "/project",
            },
        );
        assert!(
            path_item(&items, 0).ends_with("/project/tools/rg.cmd"),
            "got {}",
            path_item(&items, 0)
        );
        assert!(is_mzm(&items, 1));
    }

    #[test]
    fn parse_bash_project_relative_path_resolved() {
        let items = items_of(
            "Bash(/tools/rg.cmd *)",
            &ParseCtx {
                home: "",
                cwd: "",
                project_root: "/project",
            },
        );
        assert!(
            path_item(&items, 0).ends_with("/project/tools/rg.cmd"),
            "got {}",
            path_item(&items, 0)
        );
    }

    #[test]
    fn parse_bash_double_slash_absolute() {
        let items = items_of("Bash(//usr/bin/rg *)", &ctx_default());
        assert!(
            path_item(&items, 0).ends_with("/usr/bin/rg"),
            "got {}",
            path_item(&items, 0)
        );
    }

    #[test]
    fn parse_bash_tilde_path_resolved() {
        let items = items_of(
            "Bash(~/bin/rg *)",
            &ParseCtx {
                home: "/home/anna",
                cwd: "",
                project_root: "",
            },
        );
        assert!(
            path_item(&items, 0).ends_with("/home/anna/bin/rg"),
            "got {}",
            path_item(&items, 0)
        );
    }

    #[test]
    fn parse_bash_tilde_path_drops_on_unknown_home() {
        let parsed = parse_single_rule(
            "Bash(~/bin/rg *)",
            &ParseCtx {
                home: "",
                cwd: "",
                project_root: "",
            },
        );
        assert!(parsed.is_none(), "tilde-rooted arg0 with empty home should be dropped");
    }

    #[test]
    fn parse_bash_wildcard_all_is_mzm() {
        let items = items_of("Bash(*)", &ctx_default());
        assert_eq!(items.len(), 1);
        assert!(is_mzm(&items, 0));
    }

    #[test]
    fn parse_bash_double_star_alone_is_mzm() {
        let items = items_of("Bash(**)", &ctx_default());
        assert_eq!(items.len(), 1);
        assert!(is_mzm(&items, 0));
    }

    #[test]
    fn parse_bash_mid_star_is_match_one() {
        let items = items_of("Bash(git -C * status)", &ctx_default());
        assert_eq!(items.len(), 4);
        assert_eq!(name_item(&items, 0), "git");
        assert_eq!(arg_item(&items, 1), "-C");
        assert!(is_one(&items, 2));
        assert_eq!(arg_item(&items, 3), "status");
    }

    #[test]
    fn parse_bash_mid_double_star_is_zero_or_more() {
        let items = items_of("Bash(git ** status)", &ctx_default());
        assert_eq!(name_item(&items, 0), "git");
        assert!(is_mzm(&items, 1));
        assert_eq!(arg_item(&items, 2), "status");
    }

    #[test]
    fn parse_bash_trailing_star_is_zero_or_more() {
        let items = items_of("Bash(foo *)", &ctx_default());
        assert_eq!(items.len(), 2);
        assert_eq!(name_item(&items, 0), "foo");
        assert!(is_mzm(&items, 1));
    }

    #[test]
    fn parse_bash_trailing_double_star_is_zero_or_more() {
        let items = items_of("Bash(foo **)", &ctx_default());
        assert_eq!(items.len(), 2);
        assert_eq!(name_item(&items, 0), "foo");
        assert!(is_mzm(&items, 1));
    }

    #[test]
    fn parse_bash_readonly_dropped() {
        let parsed = parse_single_rule("Bash(readonly)", &ctx_default());
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_bash_readonly_wildcard_dropped() {
        let parsed = parse_single_rule("Bash(readonly *)", &ctx_default());
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_bash_readonly_with_path_dropped() {
        let parsed = parse_single_rule(
            "Bash(/bin/readonly)",
            &ParseCtx {
                home: "",
                cwd: "",
                project_root: "/project",
            },
        );
        assert!(
            parsed.is_none(),
            "path-qualified `/bin/readonly` → basename `readonly` → dropped"
        );
    }

    #[test]
    fn parse_bash_empty_parens_none() {
        assert!(parse_single_rule("Bash()", &ctx_default()).is_none());
    }

    #[test]
    fn parse_bash_arg_with_glob() {
        let items = items_of("Bash(git branch foo*)", &ctx_default());
        assert_eq!(name_item(&items, 0), "git");
        assert_eq!(arg_item(&items, 1), "branch");
        assert_eq!(arg_item(&items, 2), "foo*");
    }

    #[test]
    fn parse_bash_colon_wildcard_with_path() {
        // Colon-wildcard normalization runs before arg0 classification, so the
        // path-containing token is still resolved as a path.
        let items = items_of(
            "Bash(./tools/rg.cmd:*)",
            &ParseCtx {
                home: "",
                cwd: "/project",
                project_root: "/project",
            },
        );
        assert!(path_item(&items, 0).ends_with("/project/tools/rg.cmd"));
        assert!(is_mzm(&items, 1));
    }

    #[test]
    fn parse_bash_windows_backslash_path() {
        // `normalize_separators` runs inside `resolve_rule_path`, so a
        // backslash-written rule routes to the correct 4-tier branch.
        let items = items_of(
            "Bash(.\\tools\\rg.cmd *)",
            &ParseCtx {
                home: "",
                cwd: "/project",
                project_root: "/project",
            },
        );
        assert!(
            path_item(&items, 0).ends_with("/project/tools/rg.cmd"),
            "got {}",
            path_item(&items, 0)
        );
    }
}
