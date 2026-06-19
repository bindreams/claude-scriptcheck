//! `BashFilter` — item-based filter for Bash commands.
//!
//! Each `Bash(<inner>)` rule is tokenized at parse time and classified into
//! an ordered list of [`BashFilterItem`]: `Arg0(Name | Path)`, `Arg(literal
//! or glob)`, `MatchOne` (`*` in non-trailing position), `MatchZeroOrMore`
//! (`**` anywhere or trailing `*`). Matching runs token-by-token with
//! backtracking for `MatchZeroOrMore`.
//!
//! Parsing lives in `src/permission.rs`. This module owns the data model,
//! matching algorithm, and `reconstruct_data` / `to_rule_string` round-trip.

use crate::impl_filter;
use crate::path_util;

/// A Bash command filter built from classified rule items.
#[derive(Debug, Clone)]
pub struct BashFilter {
    pub items: Vec<BashFilterItem>,
}

#[derive(Debug, Clone)]
pub enum BashFilterItem {
    /// Command-name (arg0) position. Present when the rule has a concrete
    /// first token that isn't `*` / `**`.
    Arg0(Arg0Pattern),
    /// A literal argument token, possibly a glob (matched via `glob_match`
    /// iff the token contains `*`).
    Arg(String),
    /// `*` in non-trailing position — match exactly one token.
    MatchOne,
    /// `**` in any position, or a trailing `*` — match zero or more tokens.
    MatchZeroOrMore,
}

/// The matching strategy for a rule's arg0.
#[derive(Debug, Clone)]
pub enum Arg0Pattern {
    /// The rule's first token had no slash. Matched by basename, with
    /// Windows PATHEXT suffix stripping (both sides). The stored value
    /// has its PATHEXT suffix already stripped at parse time (unless it
    /// contains a glob `*`).
    Name(String),
    /// The rule's first token had a slash. Matched by canonical absolute
    /// path. The stored value is already resolved (4-tier scheme +
    /// `best_effort_canonicalize`). Bare-name command invocations do not
    /// match. PATHEXT tolerance applies: stripping both sides' basename
    /// PATHEXT and re-comparing.
    Path(String),
}

impl BashFilter {
    pub fn from_items(items: Vec<BashFilterItem>) -> Self {
        Self { items }
    }

    /// Returns true if this filter matches a command with the given raw arg0
    /// and static args, resolved against `cwd` for path-scoped rules.
    pub fn matches(&self, raw_arg0: &str, args: &[String], cwd: &str) -> bool {
        // Concatenate arg0 and args into one slice — the matcher treats them
        // uniformly. Allocation is fine: hooks run per-tool-call, not hot path.
        let mut tokens: Vec<&str> = Vec::with_capacity(args.len() + 1);
        tokens.push(raw_arg0);
        for a in args {
            tokens.push(a.as_str());
        }
        match_items(&self.items, &tokens, cwd)
    }

    /// Returns true if this filter matches a dynamic-arg0 command (i.e. one
    /// whose command name couldn't be statically resolved).
    ///
    /// The items list is walked against the *static args only* — arg0 is
    /// treated as missing, so items starting with `Arg0(...)` (a concrete
    /// name or path) cannot match. Items starting with `MatchZeroOrMore` can
    /// still match if the remaining items align with `args` (so e.g.
    /// `Bash(** foo)` with args `["foo"]` matches — `MatchZeroOrMore` skips
    /// zero tokens, then `Arg("foo")` consumes `"foo"`).
    pub fn matches_dynamic_arg0(&self, args: &[String], cwd: &str) -> bool {
        let tokens: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match_items(&self.items, &tokens, cwd)
    }

    /// Reconstruct the rule-string payload — e.g. `git status *` or
    /// `//abs/path *`.
    pub fn reconstruct_data(&self) -> String {
        let last_idx = self.items.len().saturating_sub(1);
        let mut out = String::new();
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            match item {
                BashFilterItem::Arg0(Arg0Pattern::Name(s)) => out.push_str(s),
                BashFilterItem::Arg0(Arg0Pattern::Path(abs)) => {
                    // Re-emit with the `//` prefix so the round-trip rule
                    // string is unambiguous (matches Read/Write/Edit
                    // resolved-path convention). Trim any leading slashes
                    // first: `/abs/x` and `//abs/x` (the double-slash form
                    // can leak out of `best_effort_canonicalize` for
                    // non-existent paths on Unix) both normalize to
                    // `//abs/x` in the rule-string form. Windows drive-letter
                    // paths like `C:/foo` have no leading slash and pass
                    // through as `//C:/foo`.
                    out.push('/');
                    out.push('/');
                    out.push_str(abs.trim_start_matches('/'));
                }
                BashFilterItem::Arg(s) => out.push_str(s),
                BashFilterItem::MatchOne => out.push('*'),
                BashFilterItem::MatchZeroOrMore => {
                    // Use `*` at the tail and `**` elsewhere. Today's
                    // parse accepts either form at the tail; the `*`
                    // form is shorter and matches pre-fix log output.
                    if i == last_idx {
                        out.push('*');
                    } else {
                        out.push_str("**");
                    }
                }
            }
        }
        out
    }
}

impl_filter!(BashFilter, "Bash", owned);

impl Arg0Pattern {
    fn matches(&self, raw_arg0: &str, cwd: &str) -> bool {
        match self {
            Arg0Pattern::Name(rule_name) => {
                let basename = basename_of(raw_arg0);
                let stripped = path_util::strip_pathext_suffix(basename);
                if rule_name.contains('*') {
                    glob_match::glob_match(rule_name, stripped)
                } else {
                    names_equal(stripped, rule_name)
                }
            }
            Arg0Pattern::Path(rule_abs) => {
                // Bare-name command invocation: path-scoped rule does not match.
                if !raw_arg0.contains('/') && !raw_arg0.contains('\\') {
                    return false;
                }

                let normalized = path_util::normalize_separators(raw_arg0);
                let resolved = if path_util::is_absolute(&normalized) {
                    normalized
                } else {
                    format!("{cwd}/{normalized}")
                };
                // Canonicalize both sides. Normally `rule_abs` is already
                // canonical (set by `permission::classify_arg0` at parse time),
                // making this a no-op idempotent pass — but we canonicalize
                // defensively so unit tests that build `Arg0::Path` directly
                // see the same shape as parser-produced filters.
                let lhs = crate::canonicalize::best_effort_canonicalize(&resolved);
                let rhs = crate::canonicalize::best_effort_canonicalize(rule_abs);

                let lhs = lhs.trim_end_matches('/');
                let rhs = rhs.trim_end_matches('/');

                if path_match(lhs, rhs) {
                    return true;
                }

                // PATHEXT tolerance: strip either side's basename PATHEXT
                // suffix and re-compare, so `Bash(./bin/rg *)` matches
                // `./bin/rg.cmd` and vice versa.
                let lhs_stripped = strip_pathext_on_basename(lhs);
                let rhs_stripped = strip_pathext_on_basename(rhs);
                path_match(&lhs_stripped, &rhs_stripped)
            }
        }
    }
}

fn match_items(items: &[BashFilterItem], tokens: &[&str], cwd: &str) -> bool {
    if items.is_empty() {
        return tokens.is_empty();
    }
    match &items[0] {
        BashFilterItem::Arg0(pat) => match tokens.first() {
            Some(t) if pat.matches(t, cwd) => match_items(&items[1..], &tokens[1..], cwd),
            _ => false,
        },
        BashFilterItem::Arg(s) => match tokens.first() {
            Some(t) if arg_matches(s, t) => match_items(&items[1..], &tokens[1..], cwd),
            _ => false,
        },
        BashFilterItem::MatchOne => {
            if tokens.is_empty() {
                false
            } else {
                match_items(&items[1..], &tokens[1..], cwd)
            }
        }
        BashFilterItem::MatchZeroOrMore => {
            for skip in 0..=tokens.len() {
                if match_items(&items[1..], &tokens[skip..], cwd) {
                    return true;
                }
            }
            false
        }
    }
}

fn arg_matches(pattern: &str, actual: &str) -> bool {
    if pattern.contains('*') {
        glob_match::glob_match(pattern, actual)
    } else {
        pattern == actual
    }
}

fn basename_of(path: &str) -> &str {
    match path.rfind('/').or_else(|| path.rfind('\\')) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn strip_pathext_on_basename(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => {
            let (dir, base) = path.split_at(i + 1);
            format!("{dir}{}", path_util::strip_pathext_suffix(base))
        }
        None => path_util::strip_pathext_suffix(path).to_string(),
    }
}

#[cfg(windows)]
fn names_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(not(windows))]
fn names_equal(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(windows)]
fn paths_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(not(windows))]
fn paths_equal(a: &str, b: &str) -> bool {
    a == b
}

/// Path-aware compare: delegates to `paths_equal` when `rule_pattern` has no
/// wildcard, otherwise uses `glob_match` (which interprets `*` / `**` with
/// the same semantics Read/Write/Edit rules use). Glob matching is always
/// case-sensitive because `glob_match` has no case-fold option; that's
/// consistent with Read/Write/Edit behavior. `lhs` is the command side,
/// `rule_pattern` is the rule side.
fn path_match(lhs: &str, rule_pattern: &str) -> bool {
    if rule_pattern.contains('*') || rule_pattern.contains('?') {
        glob_match::glob_match(rule_pattern, lhs)
    } else {
        paths_equal(lhs, rule_pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;

    fn name(s: &str) -> BashFilterItem {
        BashFilterItem::Arg0(Arg0Pattern::Name(s.to_string()))
    }
    fn path(s: &str) -> BashFilterItem {
        BashFilterItem::Arg0(Arg0Pattern::Path(s.to_string()))
    }
    fn arg(s: &str) -> BashFilterItem {
        BashFilterItem::Arg(s.to_string())
    }

    fn strs(ss: &[&str]) -> Vec<String> {
        ss.iter().map(|s| s.to_string()).collect()
    }

    // Arg0::Name matching =============================================================================================

    #[test]
    fn arg0_name_matches_bare() {
        let f = BashFilter::from_items(vec![name("rg")]);
        assert!(f.matches("rg", &[], "/cwd"));
    }

    #[test]
    fn arg0_name_matches_with_exe() {
        let f = BashFilter::from_items(vec![name("rg")]);
        assert!(f.matches("rg.exe", &[], "/cwd"));
    }

    #[test]
    fn arg0_name_matches_with_cmd() {
        let f = BashFilter::from_items(vec![name("rg")]);
        assert!(f.matches("rg.cmd", &[], "/cwd"));
    }

    #[test]
    fn arg0_name_matches_with_path_prefix() {
        let f = BashFilter::from_items(vec![name("rg")]);
        assert!(f.matches("./bin/rg.cmd", &[], "/cwd"));
    }

    #[test]
    fn arg0_name_does_not_match_different_name() {
        let f = BashFilter::from_items(vec![name("rg")]);
        assert!(!f.matches("grep", &[], "/cwd"));
    }

    #[test]
    fn arg0_name_glob_preserves_literal_pathext() {
        // Glob rule names keep their literal form; command-side basename is
        // still PATHEXT-stripped before the glob match. So `py*.exe` matches
        // neither `python.exe` (stripped to `python`) nor `python.cmd`.
        let f = BashFilter::from_items(vec![name("py*.exe")]);
        assert!(!f.matches("python.exe", &[], "/cwd"));
        assert!(!f.matches("python.cmd", &[], "/cwd"));
    }

    #[test]
    fn arg0_name_glob_matches_stripped_basename() {
        let f = BashFilter::from_items(vec![name("rg*")]);
        assert!(f.matches("rg.cmd", &[], "/cwd"));
        // Glob `rg*` matches `rg` followed by anything — so `rgsomething.exe`
        // → strip → `rgsomething` → glob-matches `rg*`.
        assert!(f.matches("rgsomething.exe", &[], "/cwd"));
        // `ripgrep` does NOT start with `rg`; confirms the glob is anchored.
        assert!(!f.matches("ripgrep", &[], "/cwd"));
        assert!(!f.matches("grep", &[], "/cwd"));
    }

    // Arg0::Path matching =============================================================================================

    #[test]
    fn arg0_path_matches_resolved_command() {
        let f = BashFilter::from_items(vec![path("/abs/tools/rg.cmd")]);
        assert!(f.matches("/abs/tools/rg.cmd", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_does_not_match_bare_name() {
        let f = BashFilter::from_items(vec![path("/abs/tools/rg.cmd")]);
        assert!(!f.matches("rg.cmd", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_tolerates_pathext_difference() {
        // Rule has no extension, command has .cmd.
        let f = BashFilter::from_items(vec![path("/abs/bin/rg")]);
        assert!(f.matches("/abs/bin/rg.cmd", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_pathext_tolerance_is_symmetric() {
        // Rule has .cmd, command has no extension.
        let f = BashFilter::from_items(vec![path("/abs/bin/rg.cmd")]);
        assert!(f.matches("/abs/bin/rg", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_resolves_relative_against_cwd() {
        // Relative command path is resolved against cwd before canonicalization.
        let f = BashFilter::from_items(vec![path("/tmp/foo/rg")]);
        assert!(f.matches("./rg", &[], "/tmp/foo"));
    }

    #[test]
    fn arg0_path_with_glob_matches_via_glob_match() {
        // Rules with glob segments in paths use glob_match (parallel to
        // Read/Write/Edit). So `Bash(/opt/*/rg *)` matches any first-level
        // subdirectory of /opt whose last component is `rg`.
        let f = BashFilter::from_items(vec![path("/opt/*/rg")]);
        assert!(f.matches("/opt/tools/rg", &[], "/cwd"));
        assert!(f.matches("/opt/other/rg", &[], "/cwd"));
        assert!(!f.matches("/opt/deep/nested/rg", &[], "/cwd")); // * is single-segment
        assert!(!f.matches("/opt/tools/grep", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_with_double_star_glob_matches_nested() {
        let f = BashFilter::from_items(vec![path("/opt/**/rg")]);
        assert!(f.matches("/opt/rg", &[], "/cwd"));
        assert!(f.matches("/opt/tools/rg", &[], "/cwd"));
        assert!(f.matches("/opt/a/b/c/rg", &[], "/cwd"));
        assert!(!f.matches("/usr/rg", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_trailing_slash_normalized() {
        // Nonsense rule shape (directory path) — pinning behavior: after
        // trim_end_matches('/'), `/tools/` and `/tools` compare equal, so an
        // invocation of `/tools` (which would fail to exec as a directory
        // anyway) does match. A real command under `/tools/` (like
        // `/tools/rg`) doesn't match. Documented oddity, doesn't panic.
        let f = BashFilter::from_items(vec![path("/tools/")]);
        assert!(!f.matches("/tools/rg", &[], "/cwd"));
        assert!(f.matches("/tools", &[], "/cwd"));
    }

    #[test]
    fn arg0_path_drive_letter_absolute() {
        // Windows drive-letter path: pins behavior cross-platform. On Unix
        // this test still builds and runs because `path_clean` treats `C:`
        // as just a component — the match is purely string-based.
        let f = BashFilter::from_items(vec![path("C:/tools/rg.cmd")]);
        assert!(f.matches("C:/tools/rg.cmd", &[], "/cwd"));
        assert!(!f.matches("C:/tools/other", &[], "/cwd"));
    }

    #[cfg(windows)]
    #[test]
    fn arg0_name_case_insensitive_on_windows() {
        let f = BashFilter::from_items(vec![name("git")]);
        assert!(f.matches("GIT", &[], "/cwd"));
        assert!(f.matches("Git.exe", &[], "/cwd"));
        assert!(!f.matches("grep", &[], "/cwd"));
    }

    #[cfg(windows)]
    #[test]
    fn arg0_path_case_insensitive_on_windows() {
        let f = BashFilter::from_items(vec![path("C:/Tools/Rg.cmd")]);
        assert!(f.matches("c:/tools/rg.cmd", &[], "/cwd"));
        assert!(f.matches("C:/TOOLS/RG.CMD", &[], "/cwd"));
    }

    // Item-list matching ==============================================================================================

    #[test]
    fn match_zero_or_more_trailing() {
        let f = BashFilter::from_items(vec![name("foo"), BashFilterItem::MatchZeroOrMore]);
        assert!(f.matches("foo", &strs(&["bar", "baz"]), "/cwd"));
        assert!(f.matches("foo", &[], "/cwd"));
    }

    #[test]
    fn match_zero_or_more_middle() {
        let f = BashFilter::from_items(vec![
            name("git"),
            BashFilterItem::MatchZeroOrMore,
            arg("status"),
        ]);
        assert!(f.matches("git", &strs(&["-C", "dir", "status"]), "/cwd"));
        assert!(f.matches("git", &strs(&["status"]), "/cwd"));
        assert!(!f.matches("git", &strs(&["log"]), "/cwd"));
    }

    #[test]
    fn match_one_consumes_single_token() {
        let f = BashFilter::from_items(vec![
            name("git"),
            arg("-C"),
            BashFilterItem::MatchOne,
            arg("status"),
        ]);
        assert!(f.matches("git", &strs(&["-C", "some/path", "status"]), "/cwd"));
        assert!(!f.matches("git", &strs(&["-C", "status"]), "/cwd"));
    }

    #[test]
    fn wildcard_all_matches_anything() {
        let f = BashFilter::from_items(vec![BashFilterItem::MatchZeroOrMore]);
        assert!(f.matches("anything", &strs(&["at", "all"]), "/cwd"));
        assert!(f.matches("x", &[], "/cwd"));
        assert!(f.matches_dynamic_arg0(&[], "/cwd"));
        assert!(f.matches_dynamic_arg0(&strs(&["args"]), "/cwd"));
    }

    #[test]
    fn matches_dynamic_arg0_rejects_concrete_arg0() {
        let f = BashFilter::from_items(vec![name("rg")]);
        assert!(!f.matches_dynamic_arg0(&[], "/cwd"));
        assert!(!f.matches_dynamic_arg0(&strs(&["foo"]), "/cwd"));
    }

    #[test]
    fn matches_dynamic_arg0_mzm_then_arg_can_match_args() {
        // `Bash(** foo)` with dynamic arg0 + args=["foo"] → MZM consumes 0,
        // then Arg("foo") consumes "foo". Match.
        let f = BashFilter::from_items(vec![BashFilterItem::MatchZeroOrMore, arg("foo")]);
        assert!(f.matches_dynamic_arg0(&strs(&["foo"]), "/cwd"));
        assert!(!f.matches_dynamic_arg0(&strs(&["bar"]), "/cwd"));
        assert!(!f.matches_dynamic_arg0(&[], "/cwd"));
    }

    #[test]
    fn matches_dynamic_arg0_rejects_path_and_match_one() {
        let p = BashFilter::from_items(vec![path("/abs")]);
        assert!(!p.matches_dynamic_arg0(&[], "/cwd"));
        let m = BashFilter::from_items(vec![BashFilterItem::MatchOne]);
        // MatchOne requires one token — no tokens (dynamic arg0, no args) → fail.
        assert!(!m.matches_dynamic_arg0(&[], "/cwd"));
        // With one arg, MatchOne consumes it → match.
        assert!(m.matches_dynamic_arg0(&strs(&["x"]), "/cwd"));
    }

    // arg_matches glob ================================================================================================

    #[test]
    fn arg_glob_matches() {
        let f = BashFilter::from_items(vec![name("git"), arg("branch"), arg("foo*")]);
        assert!(f.matches("git", &strs(&["branch", "foobar"]), "/cwd"));
        assert!(!f.matches("git", &strs(&["branch", "bar"]), "/cwd"));
    }

    // reconstruct_data round-trip =====================================================================================

    #[test]
    fn reconstruct_data_name_with_wildcard() {
        let f = BashFilter::from_items(vec![name("foo"), BashFilterItem::MatchZeroOrMore]);
        assert_eq!(f.reconstruct_data(), "foo *");
    }

    #[test]
    fn reconstruct_data_path_emits_double_slash_prefix() {
        let f = BashFilter::from_items(vec![path("/abs/x"), BashFilterItem::MatchZeroOrMore]);
        assert_eq!(f.reconstruct_data(), "//abs/x *");
    }

    #[test]
    fn reconstruct_data_match_one_middle() {
        let f = BashFilter::from_items(vec![name("foo"), BashFilterItem::MatchOne, arg("bar")]);
        assert_eq!(f.reconstruct_data(), "foo * bar");
    }

    #[test]
    fn reconstruct_data_wildcard_all() {
        let f = BashFilter::from_items(vec![BashFilterItem::MatchZeroOrMore]);
        assert_eq!(f.reconstruct_data(), "*");
    }

    #[test]
    fn to_rule_string_includes_bash_kind() {
        let f = BashFilter::from_items(vec![name("ls"), BashFilterItem::MatchZeroOrMore]);
        assert_eq!(f.to_rule_string(), "Bash(ls *)");
    }
}
