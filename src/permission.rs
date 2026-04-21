use crate::filter::{BashFilter, EditFilter, ReadFilter, RuleSet, Verdict, WriteFilter};
use crate::permission_mode::PermissionMode;
use crate::settings::{self, Permissions};

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

pub fn parse_rules(perms: &Permissions) -> ParsedPermissions {
    let home = crate::env_hooks::hook_home()
        .map(|h| crate::path_util::normalize_separators(&h.to_string_lossy()))
        .unwrap_or_default();

    let mut parsed = ParsedPermissions::default();

    for rule_str in &perms.allow {
        push_parsed(&mut parsed, Verdict::Allow, rule_str, &home);
    }
    for rule_str in &perms.deny {
        push_parsed(&mut parsed, Verdict::Deny, rule_str, &home);
    }
    for rule_str in &perms.ask {
        push_parsed(&mut parsed, Verdict::Ask, rule_str, &home);
    }

    parsed
}

fn push_parsed(parsed: &mut ParsedPermissions, verdict: Verdict, rule_str: &str, home: &str) {
    match parse_single_rule(rule_str, home) {
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
pub fn parse_single_rule(rule: &str, home: &str) -> Option<ParsedFilter> {
    // Bare tool-level wildcards (no parentheses)
    match rule {
        "Bash" => return Some(ParsedFilter::Bash(BashFilter::wildcard_all())),
        "Read" => return Some(ParsedFilter::Read(ReadFilter::new("**".to_string()))),
        "Write" => return Some(ParsedFilter::Write(WriteFilter::new("**".to_string()))),
        "Edit" => return Some(ParsedFilter::Edit(EditFilter::new("**".to_string()))),
        _ => {}
    }

    if let Some(inner) = rule.strip_prefix("Bash(").and_then(|s| s.strip_suffix(')')) {
        let mut tokens: Vec<String> = inner.split_whitespace().map(String::from).collect();
        // Normalize Claude Code's colon-wildcard format: "cmd:*" → "cmd" "*"
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
        if tokens[0] == "readonly" {
            return None;
        }
        let filter = if tokens.last().map(|s| s.as_str()) == Some("*") && tokens.len() > 1 {
            BashFilter::new_wildcard(tokens[..tokens.len() - 1].to_vec())
        } else if tokens.len() == 1 && tokens[0] == "*" {
            BashFilter::wildcard_all()
        } else {
            BashFilter::new(tokens)
        };
        return Some(ParsedFilter::Bash(filter));
    }

    if let Some(inner) = rule.strip_prefix("Read(").and_then(|s| s.strip_suffix(')')) {
        let pattern = crate::canonicalize::best_effort_canonicalize(&expand_tilde(inner, home));
        return Some(ParsedFilter::Read(ReadFilter::new(pattern)));
    }
    if let Some(inner) = rule
        .strip_prefix("Write(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let pattern = crate::canonicalize::best_effort_canonicalize(&expand_tilde(inner, home));
        return Some(ParsedFilter::Write(WriteFilter::new(pattern)));
    }
    if let Some(inner) = rule.strip_prefix("Edit(").and_then(|s| s.strip_suffix(')')) {
        let pattern = crate::canonicalize::best_effort_canonicalize(&expand_tilde(inner, home));
        return Some(ParsedFilter::Edit(EditFilter::new(pattern)));
    }
    None
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
    let mut parsed = parse_rules(&loaded.permissions);

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

    for dir in workspace_dirs {
        let normalized = crate::path_util::normalize_separators(dir);
        let base = normalized.trim_end_matches('/');
        if base.is_empty() {
            continue;
        }

        let write_rule = format!("Write({base}/**)");
        let edit_rule = format!("Edit({base}/**)");

        if let Some(ParsedFilter::Write(f)) = parse_single_rule(&write_rule, &home) {
            perms.write.allow.push(f);
        }
        if let Some(ParsedFilter::Edit(f)) = parse_single_rule(&edit_rule, &home) {
            perms.edit.allow.push(f);
        }
    }
}

/// Test-only helper: match a pattern against a path with separator normalization.
///
/// Production code uses `PathFilter::matches`, which assumes both sides are
/// already canonical (forward-slash). This helper preserves the pre-refactor
/// call-site ergonomics for tests that want to sanity-check glob semantics
/// without threading a filter instance through.
#[doc(hidden)]
pub fn file_rule_matches(pattern: &str, path: &str) -> bool {
    let pattern = crate::path_util::normalize_separators(pattern);
    let path = crate::path_util::normalize_separators(path);
    glob_match::glob_match(&pattern, &path)
}

/// Expand a leading `~/` or bare `~` to the home directory.
/// Does NOT expand `~` in the middle of a path (e.g. `/home/user/my~project`).
/// Returns the input unchanged if `home` is empty (cannot expand).
fn expand_tilde(path: &str, home: &str) -> String {
    if home.is_empty() {
        return path.to_string();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if path == "~" {
        home.to_string()
    } else {
        path.to_string()
    }
}
