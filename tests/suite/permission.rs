use std::path::Path;

use claude_scriptcheck::filter::{BashFilter, Filter, PathFilter};
use claude_scriptcheck::permission::*;
use claude_scriptcheck::settings::Permissions;
use pretty_assertions::assert_eq;

fn make_rule(prefix: &[&str], wildcard: bool) -> BashFilter {
    BashFilter {
        prefix_tokens: prefix.iter().map(|s| s.to_string()).collect(),
        wildcard,
    }
}

fn tokens(s: &[&str]) -> Vec<String> {
    s.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn exact_match() {
    let rule = make_rule(&["git", "status"], false);
    assert!(rule.matches(&tokens(&["git", "status"])));
}

#[skuld::test]
fn exact_no_extra_args() {
    let rule = make_rule(&["git", "status"], false);
    assert!(!rule.matches(&tokens(&["git", "status", "-s"])));
}

#[skuld::test]
fn wildcard_with_extra_args() {
    let rule = make_rule(&["git", "status"], true);
    assert!(rule.matches(&tokens(&["git", "status", "-s"])));
}

#[skuld::test]
fn wildcard_exact_prefix() {
    let rule = make_rule(&["git", "status"], true);
    assert!(rule.matches(&tokens(&["git", "status"])));
}

#[skuld::test]
fn wrong_prefix() {
    let rule = make_rule(&["git", "status"], true);
    assert!(!rule.matches(&tokens(&["git", "commit"])));
}

#[skuld::test]
fn single_command_no_wildcard() {
    let rule = make_rule(&["ls"], false);
    assert!(rule.matches(&tokens(&["ls"])));
    assert!(!rule.matches(&tokens(&["ls", "-la"])));
}

#[skuld::test]
fn single_command_with_wildcard() {
    let rule = make_rule(&["ls"], true);
    assert!(rule.matches(&tokens(&["ls"])));
    assert!(rule.matches(&tokens(&["ls", "-la", "/tmp"])));
}

#[skuld::test]
fn token_with_glob() {
    let rule = make_rule(&["gcc", "-print-file-name=*"], false);
    assert!(rule.matches(&tokens(&["gcc", "-print-file-name=libgcc.a"])));
}

#[skuld::test]
fn bare_star_matches_path_with_slashes() {
    let rule = make_rule(&["git", "-C", "*", "status"], true);
    assert!(rule.matches(&tokens(&["git", "-C", "/tmp/repo", "status"])));
    assert!(rule.matches(&tokens(&["git", "-C", "/tmp/repo", "status", "-s"])));
    assert!(!rule.matches(&tokens(&["git", "-C", "/tmp/repo", "push"])));
}

#[skuld::test]
fn too_short_command() {
    let rule = make_rule(&["git", "status"], false);
    assert!(!rule.matches(&tokens(&["git"])));
}

#[skuld::test]
fn file_pattern_match() {
    assert!(file_rule_matches(
        "/tmp/claude/**",
        "/tmp/claude/foo/bar.txt"
    ));
}

#[skuld::test]
fn file_pattern_no_match() {
    assert!(!file_rule_matches("/tmp/claude/**", "/home/user/file.txt"));
}

#[skuld::test]
fn file_pattern_backslash_in_rule_matches() {
    // User-authored rules may contain backslashes on Windows
    assert!(file_rule_matches(
        "C:\\Users\\foo\\**",
        "C:/Users/foo/bar.txt"
    ));
}

#[skuld::test]
fn file_pattern_backslash_in_path_matches() {
    assert!(file_rule_matches(
        "C:/Users/foo/**",
        "C:\\Users\\foo\\bar.txt"
    ));
}

// ─── Glob matching: ** and * behavior ─────────────────────────────────────────

#[skuld::test]
fn globstar_does_not_match_base_dir() {
    assert!(!file_rule_matches("/tmp/**", "/tmp"));
}

#[skuld::test]
fn globstar_matches_single_level() {
    assert!(file_rule_matches("/tmp/**", "/tmp/a"));
}

#[skuld::test]
fn globstar_matches_nested() {
    assert!(file_rule_matches("/tmp/**", "/tmp/a/b"));
}

#[skuld::test]
fn star_matches_single_level() {
    assert!(file_rule_matches("/tmp/*", "/tmp/a"));
}

#[skuld::test]
fn star_does_not_match_nested() {
    assert!(!file_rule_matches("/tmp/*", "/tmp/a/b"));
}

#[skuld::test]
fn parse_bash_rule_exact() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(git status)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["git", "status"]);
            assert!(!rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn parse_bash_rule_wildcard() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(git status *)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["git", "status"]);
            assert!(rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn parse_then_match_trailing_wildcard() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(git status *)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            // Zero extra args
            assert!(rule.matches(&tokens(&["git", "status"])));
            // Multiple extra args
            assert!(rule.matches(&tokens(&["git", "status", "-s", "--porcelain"])));
            // Wrong prefix
            assert!(!rule.matches(&tokens(&["git", "commit", "-m", "msg"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn bash_star_parens_matches_any_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(*)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(rule.prefix_tokens.is_empty());
            assert!(rule.wildcard);
            assert!(rule.matches(&tokens(&["ls"])));
            assert!(rule.matches(&tokens(&["git", "push", "origin", "main"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn parse_read_rule(#[fixture(temp_dir)] dir: &Path) {
    let base = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(Path::new(dir).join("src")).unwrap();

    let parsed = parse_single_rule("Read(~/src/**)", &base).unwrap();
    match parsed {
        ParsedFilter::Read(pat) => assert_eq!(pat.pattern(), format!("{base}/src/**")),
        _ => panic!("expected Read rule"),
    }
}

#[skuld::test]
fn parse_write_rule(#[fixture(temp_dir)] dir: &Path) {
    let base = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(Path::new(dir).join("claude")).unwrap();

    let rule = format!("Write({base}/claude/**)");
    let parsed = parse_single_rule(&rule, "/unused").unwrap();
    match parsed {
        ParsedFilter::Write(pat) => assert_eq!(pat.pattern(), format!("{base}/claude/**")),
        _ => panic!("expected Write rule"),
    }
}

#[skuld::test]
fn parse_readonly_skipped() {
    let home = "/home/test";
    assert!(parse_single_rule("Bash(readonly)", home).is_none());
    assert!(parse_single_rule("Bash(readonly *)", home).is_none());
}

#[skuld::test]
fn parse_irrelevant_rule_skipped() {
    let home = "/home/test";
    assert!(parse_single_rule("WebSearch", home).is_none());
    assert!(parse_single_rule("mcp__Glean__*", home).is_none());
}

// ─── Bare rules (tool-level wildcards) ────────────────────────────────────────

#[skuld::test]
fn bare_bash_matches_any_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(rule.prefix_tokens.is_empty());
            assert!(rule.wildcard);
            assert!(rule.matches(&tokens(&["ls"])));
            assert!(rule.matches(&tokens(&["git", "push"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn bare_read_matches_any_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Read", home).unwrap();
    match parsed {
        ParsedFilter::Read(pat) => {
            assert!(pat.matches("/any/path/at/all"));
            assert!(pat.matches("/tmp/file.txt"));
            assert!(pat.matches("C:/Users/foo/bar.txt"));
        }
        _ => panic!("expected Read rule"),
    }
}

#[skuld::test]
fn bare_write_matches_any_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Write", home).unwrap();
    match parsed {
        ParsedFilter::Write(pat) => {
            assert!(pat.matches("/any/path"));
        }
        _ => panic!("expected Write rule"),
    }
}

#[skuld::test]
fn bare_edit_matches_any_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Edit", home).unwrap();
    match parsed {
        ParsedFilter::Edit(pat) => {
            assert!(pat.matches("/any/path"));
        }
        _ => panic!("expected Edit rule"),
    }
}

// ─── BashFilter::to_rule_string ─────────────────────────────────────────────────

#[skuld::test]
fn to_rule_string_exact() {
    assert_eq!(
        make_rule(&["git", "status"], false).to_rule_string(),
        "Bash(git status)"
    );
}

#[skuld::test]
fn to_rule_string_wildcard() {
    assert_eq!(
        make_rule(&["git", "status"], true).to_rule_string(),
        "Bash(git status *)"
    );
}

#[skuld::test]
fn to_rule_string_catch_all() {
    assert_eq!(make_rule(&[], true).to_rule_string(), "Bash(*)");
}

#[skuld::test]
fn to_rule_string_single_command() {
    assert_eq!(make_rule(&["ls"], false).to_rule_string(), "Bash(ls)");
}

// ─── parse_rules: ask rules ──────────────────────────────────────────────────

#[skuld::test]
fn parse_rules_with_ask_bash() {
    let perms = Permissions {
        allow: vec![],
        deny: vec![],
        ask: vec!["Bash(rm *)".into()],
        ..Default::default()
    };
    let parsed = parse_rules(&perms);
    assert_eq!(parsed.bash.ask.len(), 1);
    assert_eq!(parsed.bash.ask[0].prefix_tokens, vec!["rm"]);
    assert!(parsed.bash.ask[0].wildcard);
}

#[skuld::test]
fn parse_rules_with_ask_read(#[fixture(temp_dir)] dir: &Path) {
    let base = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );

    let perms = Permissions {
        allow: vec![],
        deny: vec![],
        ask: vec![format!("Read({base}/**)")],
        ..Default::default()
    };
    let parsed = parse_rules(&perms);
    assert_eq!(parsed.read.ask.len(), 1);
    assert_eq!(parsed.read.ask[0].pattern(), format!("{base}/**"));
}

#[skuld::test]
fn parse_rules_with_ask_write_and_edit(#[fixture(temp_dir)] dir: &Path) {
    let base = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(Path::new(dir).join("src")).unwrap();

    let perms = Permissions {
        allow: vec![],
        deny: vec![],
        ask: vec![format!("Write({base}/**)"), format!("Edit({base}/src/**)")],
        ..Default::default()
    };
    let parsed = parse_rules(&perms);
    assert_eq!(parsed.write.ask.len(), 1);
    assert_eq!(parsed.write.ask[0].pattern(), format!("{base}/**"));
    assert_eq!(parsed.edit.ask.len(), 1);
    assert_eq!(parsed.edit.ask[0].pattern(), format!("{base}/src/**"));
}

// ─── Double-star (**) multi-token wildcard ────────────────────────────────────

#[skuld::test]
fn doublestar_matches_zero_tokens() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(rule.matches(&tokens(&["curl", "-X", "POST", "https://example.com"])));
}

#[skuld::test]
fn doublestar_matches_one_token() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(rule.matches(&tokens(&[
        "curl",
        "-s",
        "-X",
        "POST",
        "https://example.com"
    ])));
}

#[skuld::test]
fn doublestar_matches_multiple_tokens() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(rule.matches(&tokens(&[
        "curl",
        "-s",
        "-S",
        "-H",
        "Content-Type: application/json",
        "-X",
        "POST",
        "https://example.com"
    ])));
}

#[skuld::test]
fn doublestar_at_start() {
    let rule = make_rule(&["**", "-X", "POST"], true);
    assert!(rule.matches(&tokens(&["curl", "-X", "POST", "https://example.com"])));
}

#[skuld::test]
fn doublestar_no_match_when_suffix_differs() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(!rule.matches(&tokens(&["curl", "-s", "-X", "GET", "https://example.com"])));
}

#[skuld::test]
fn doublestar_alone_matches_any_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(**)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(rule.matches(&tokens(&["ls"])));
            assert!(rule.matches(&tokens(&["git", "status", "-s"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn trailing_doublestar_without_wildcard() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl **)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(!rule.wildcard);
            assert_eq!(rule.prefix_tokens, vec!["curl", "**"]);
            assert!(rule.matches(&tokens(&["curl"])));
            assert!(rule.matches(&tokens(&["curl", "foo"])));
            assert!(rule.matches(&tokens(&["curl", "foo", "bar"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn trailing_doublestar_without_wildcard_rejects_wrong_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl **)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(!rule.matches(&tokens(&["wget"])));
            assert!(!rule.matches(&tokens(&["wget", "-O", "file"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn trailing_doublestar_without_wildcard_empty_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl **)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(!rule.matches(&tokens(&[])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn doublestar_parse_roundtrip() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl ** -X POST *)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["curl", "**", "-X", "POST"]);
            assert!(rule.wildcard);
            assert_eq!(rule.to_rule_string(), "Bash(curl ** -X POST *)");
        }
        _ => panic!("expected Bash rule"),
    }
}

// ─── Multiple double-stars in one rule ───────────────────────────────────────

#[skuld::test]
fn multiple_doublestars_both_skip_zero() {
    let rule = make_rule(&["curl", "**", "-X", "**", "POST"], false);
    assert!(rule.matches(&tokens(&["curl", "-X", "POST"])));
}

#[skuld::test]
fn multiple_doublestars_first_skips() {
    let rule = make_rule(&["curl", "**", "-X", "**", "POST"], false);
    assert!(rule.matches(&tokens(&["curl", "-s", "-X", "POST"])));
}

#[skuld::test]
fn multiple_doublestars_second_skips() {
    let rule = make_rule(&["curl", "**", "-X", "**", "POST"], false);
    assert!(rule.matches(&tokens(&["curl", "-X", "GET", "POST"])));
}

#[skuld::test]
fn multiple_doublestars_both_skip() {
    let rule = make_rule(&["curl", "**", "-X", "**", "POST"], false);
    assert!(rule.matches(&tokens(&[
        "curl",
        "-s",
        "-S",
        "-X",
        "-H",
        "Accept: */*",
        "POST"
    ])));
}

#[skuld::test]
fn multiple_doublestars_no_match_missing_literal() {
    let rule = make_rule(&["curl", "**", "-X", "**", "POST"], false);
    assert!(!rule.matches(&tokens(&["curl", "-s", "-X", "GET"])));
}

#[skuld::test]
fn multiple_doublestars_rejects_trailing() {
    let rule = make_rule(&["curl", "**", "-X", "**", "POST"], false);
    assert!(!rule.matches(&tokens(&["curl", "-X", "POST", "https://example.com"])));
}

#[skuld::test]
fn doublestar_insufficient_tokens_for_suffix() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], false);
    assert!(!rule.matches(&tokens(&["curl", "-X"])));
}

// ─── Double-star with trailing wildcard (parse-then-match) ───────────────────

#[skuld::test]
fn doublestar_with_trailing_wildcard_both_consume() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl ** -X POST *)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(rule.matches(&tokens(&[
                "curl",
                "-s",
                "-S",
                "-X",
                "POST",
                "https://example.com",
                "-d",
                "body"
            ])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn doublestar_with_trailing_wildcard_no_trailing_args() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl ** -X POST *)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(rule.matches(&tokens(&["curl", "-X", "POST"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn doublestar_with_trailing_wildcard_wrong_method() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl ** -X POST *)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert!(!rule.matches(&tokens(&["curl", "-s", "-X", "GET", "https://example.com"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

// ─── Tilde expansion in file rules ────────────────────────────────────────────

#[skuld::test]
fn tilde_in_middle_of_path_not_expanded(#[fixture(temp_dir)] dir: &Path) {
    let home = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    // Create a directory with a tilde in its name
    let tilde_dir = dir.join("my~project");
    std::fs::create_dir(&tilde_dir).unwrap();

    let rule = format!("Read({home}/my~project/**)");
    let parsed = parse_single_rule(&rule, "/unused").unwrap();
    match parsed {
        ParsedFilter::Read(pat) => {
            let pattern = pat.pattern();
            assert!(
                pattern.contains("my~project"),
                "tilde in middle of path should not be expanded, got: {pattern}"
            );
        }
        _ => panic!("expected Read rule"),
    }
}

#[skuld::test]
fn tilde_prefix_expanded_in_read_rule(#[fixture(temp_dir)] dir: &Path) {
    let home = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(dir.join("Documents")).unwrap();

    let parsed = parse_single_rule("Read(~/Documents/**)", &home).unwrap();
    match parsed {
        ParsedFilter::Read(pat) => assert_eq!(pat.pattern(), format!("{home}/Documents/**")),
        _ => panic!("expected Read rule"),
    }
}

#[skuld::test]
fn bare_tilde_expanded(#[fixture(temp_dir)] dir: &Path) {
    let home = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    let parsed = parse_single_rule("Read(~)", &home).unwrap();
    match parsed {
        ParsedFilter::Read(pat) => assert_eq!(pat.pattern(), home),
        _ => panic!("expected Read rule"),
    }
}

#[skuld::test]
fn tilde_prefix_expanded_in_write_rule(#[fixture(temp_dir)] dir: &Path) {
    let home = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(dir.join("out")).unwrap();

    let parsed = parse_single_rule("Write(~/out/**)", &home).unwrap();
    match parsed {
        ParsedFilter::Write(pat) => assert_eq!(pat.pattern(), format!("{home}/out/**")),
        _ => panic!("expected Write rule"),
    }
}

#[skuld::test]
fn tilde_prefix_expanded_in_edit_rule(#[fixture(temp_dir)] dir: &Path) {
    let home = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(dir.join("config")).unwrap();

    let parsed = parse_single_rule("Edit(~/config/**)", &home).unwrap();
    match parsed {
        ParsedFilter::Edit(pat) => assert_eq!(pat.pattern(), format!("{home}/config/**")),
        _ => panic!("expected Edit rule"),
    }
}

#[skuld::test]
fn tilde_rule_dropped_when_home_empty() {
    // B3: when home is unknown (e.g. Windows without CLAUDE_SCRIPTCHECK_HOOK_HOME
    // and with `dirs::home_dir()` unavailable), a tilde-rooted rule cannot be
    // expanded. Silently keeping `~/foo` as the literal pattern produces a dead
    // rule that matches nothing. Drop it and surface a warning.
    let parsed = parse_single_rule("Read(~/foo)", "");
    assert!(parsed.is_none(), "tilde rule should be dropped when home is empty");
}

#[skuld::test]
fn bare_tilde_rule_dropped_when_home_empty() {
    // B3: same treatment for bare `~`.
    let parsed = parse_single_rule("Read(~)", "");
    assert!(parsed.is_none());
}

#[skuld::test]
fn non_tilde_rule_unaffected_by_empty_home() {
    // B3 guardrail: rules without a tilde prefix parse normally even with home empty.
    let parsed = parse_single_rule("Read(/absolute/foo)", "");
    assert!(parsed.is_some());
}

// ─── Colon-wildcard format (Claude Code's native format) ─────────────────────

#[skuld::test]
fn parse_colon_wildcard_single_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(grep:*)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["grep"]);
            assert!(rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn parse_colon_wildcard_multi_token() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(git status:*)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["git", "status"]);
            assert!(rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn parse_colon_wildcard_relative_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(./bazel.cmd build:*)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["./bazel.cmd", "build"]);
            assert!(rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn parse_colon_wildcard_preserves_glob_in_prefix() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(gcc -print-file-name=*:*)", home).unwrap();
    match parsed {
        ParsedFilter::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["gcc", "-print-file-name=*"]);
            assert!(rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}

// ─── inject_accept_edits_rules ────────────────────────────────────────────────

#[skuld::test]
fn inject_empty_workspace_dirs() {
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &[]);
    assert!(perms.write.allow.is_empty());
    assert!(perms.edit.allow.is_empty());
}

#[skuld::test]
fn inject_single_dir(#[fixture(temp_dir)] dir: &Path) {
    let canonical = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &[canonical.clone()]);
    assert_eq!(perms.write.allow.len(), 1);
    assert_eq!(perms.edit.allow.len(), 1);
    assert_eq!(perms.write.allow[0].pattern(), format!("{canonical}/**"));
    assert_eq!(perms.edit.allow[0].pattern(), format!("{canonical}/**"));
}

#[skuld::test]
fn inject_multiple_dirs(#[fixture(temp_dir)] dir: &Path) {
    let base = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    let sub1 = dir.join("sub1");
    let sub2 = dir.join("sub2");
    std::fs::create_dir(&sub1).unwrap();
    std::fs::create_dir(&sub2).unwrap();
    let c1 = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(&sub1).unwrap().to_string_lossy(),
    );
    let c2 = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(&sub2).unwrap().to_string_lossy(),
    );
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &[base, c1.clone(), c2.clone()]);
    assert_eq!(perms.write.allow.len(), 3);
    assert!(perms.write.allow[1].pattern().starts_with(&c1));
    assert!(perms.write.allow[2].pattern().starts_with(&c2));
}

#[skuld::test]
fn inject_dir_with_trailing_slash(#[fixture(temp_dir)] dir: &Path) {
    let canonical = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    let with_slash = format!("{canonical}/");
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &[with_slash]);
    // Should not produce /path//**
    assert!(
        !perms.write.allow[0].pattern().contains("//**"),
        "double slash in pattern: {}",
        perms.write.allow[0].pattern()
    );
    assert_eq!(perms.write.allow[0].pattern(), format!("{canonical}/**"));
}

#[skuld::test]
fn inject_does_not_add_bash_or_read_rules() {
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["/tmp/project".to_string()]);
    assert!(perms.bash.allow.is_empty());
    assert!(perms.read.allow.is_empty());
}

#[skuld::test]
fn inject_root_dir_skipped() {
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["/".to_string()]);
    // Root directory "/" is intentionally skipped to prevent Write(/**) which would
    // auto-allow writes to every file on the filesystem
    assert!(perms.write.allow.is_empty());
    assert!(perms.edit.allow.is_empty());
}

// ─── B7: drive-root / UNC-root skipping ──────────────────────────────────────

#[skuld::test]
fn inject_drive_root_forward_slash_skipped() {
    // B7: C:/ as workspace would produce Write(C:/**), allowing everything on the drive.
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["C:/".to_string()]);
    assert!(perms.write.allow.is_empty());
    assert!(perms.edit.allow.is_empty());
}

#[skuld::test]
fn inject_drive_root_backslash_skipped() {
    // B7: C:\\ (backslash form) — same rationale.
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["C:\\".to_string()]);
    assert!(perms.write.allow.is_empty());
    assert!(perms.edit.allow.is_empty());
}

#[skuld::test]
fn inject_unc_share_root_skipped() {
    // B7: //server/share and \\server\share forms — same rationale.
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["//server/share".to_string()]);
    assert!(perms.write.allow.is_empty());

    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["\\\\server\\share".to_string()]);
    assert!(perms.write.allow.is_empty());
}

#[skuld::test]
fn inject_bare_drive_goes_through() {
    // B7 guardrail: bare "C:" is relative (not a root) and must NOT be skipped.
    // Preserves the pre-B7 behavior where bare `C:` produced a literal subdir rule.
    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &["C:".to_string()]);
    assert_eq!(perms.write.allow.len(), 1);
    assert_eq!(perms.edit.allow.len(), 1);
}

#[skuld::test]
fn injected_rules_match_workspace_file(#[fixture(temp_dir)] dir: &Path) {
    let canonical = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(dir).unwrap().to_string_lossy(),
    );
    std::fs::create_dir(dir.join("src")).unwrap();

    let mut perms = ParsedPermissions::default();
    inject_accept_edits_rules(&mut perms, &[canonical.clone()]);

    // The ephemeral rule should match files within the workspace
    let file_in_workspace = format!("{canonical}/src/main.rs");
    assert!(perms.write.allow[0].matches(&file_in_workspace));

    // But not files outside the workspace
    assert!(!perms.write.allow[0].matches("/etc/passwd"));
}
