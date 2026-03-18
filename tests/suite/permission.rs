use std::path::Path;

use claude_scriptcheck::permission::*;
use claude_scriptcheck::settings::Permissions;
use pretty_assertions::assert_eq;

fn make_rule(prefix: &[&str], wildcard: bool) -> BashRule {
    BashRule {
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
    assert!(bash_rule_matches(&rule, &tokens(&["git", "status"])));
}

#[skuld::test]
fn exact_no_extra_args() {
    let rule = make_rule(&["git", "status"], false);
    assert!(!bash_rule_matches(&rule, &tokens(&["git", "status", "-s"])));
}

#[skuld::test]
fn wildcard_with_extra_args() {
    let rule = make_rule(&["git", "status"], true);
    assert!(bash_rule_matches(&rule, &tokens(&["git", "status", "-s"])));
}

#[skuld::test]
fn wildcard_exact_prefix() {
    let rule = make_rule(&["git", "status"], true);
    assert!(bash_rule_matches(&rule, &tokens(&["git", "status"])));
}

#[skuld::test]
fn wrong_prefix() {
    let rule = make_rule(&["git", "status"], true);
    assert!(!bash_rule_matches(&rule, &tokens(&["git", "commit"])));
}

#[skuld::test]
fn single_command_no_wildcard() {
    let rule = make_rule(&["ls"], false);
    assert!(bash_rule_matches(&rule, &tokens(&["ls"])));
    assert!(!bash_rule_matches(&rule, &tokens(&["ls", "-la"])));
}

#[skuld::test]
fn single_command_with_wildcard() {
    let rule = make_rule(&["ls"], true);
    assert!(bash_rule_matches(&rule, &tokens(&["ls"])));
    assert!(bash_rule_matches(&rule, &tokens(&["ls", "-la", "/tmp"])));
}

#[skuld::test]
fn token_with_glob() {
    let rule = make_rule(&["gcc", "-print-file-name=*"], false);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["gcc", "-print-file-name=libgcc.a"])
    ));
}

#[skuld::test]
fn bare_star_matches_path_with_slashes() {
    let rule = make_rule(&["git", "-C", "*", "status"], true);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["git", "-C", "/tmp/repo", "status"])
    ));
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["git", "-C", "/tmp/repo", "status", "-s"])
    ));
    assert!(!bash_rule_matches(
        &rule,
        &tokens(&["git", "-C", "/tmp/repo", "push"])
    ));
}

#[skuld::test]
fn too_short_command() {
    let rule = make_rule(&["git", "status"], false);
    assert!(!bash_rule_matches(&rule, &tokens(&["git"])));
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
        ParsedRule::Bash(rule) => {
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
        ParsedRule::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["git", "status"]);
            assert!(rule.wildcard);
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
        ParsedRule::Read(pat) => assert_eq!(pat, format!("{base}/src/**")),
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
        ParsedRule::Write(pat) => assert_eq!(pat, format!("{base}/claude/**")),
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
        ParsedRule::Bash(rule) => {
            assert!(rule.prefix_tokens.is_empty());
            assert!(rule.wildcard);
            assert!(bash_rule_matches(&rule, &tokens(&["ls"])));
            assert!(bash_rule_matches(&rule, &tokens(&["git", "push"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn bare_read_matches_any_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Read", home).unwrap();
    match parsed {
        ParsedRule::Read(pat) => {
            assert!(file_rule_matches(&pat, "/any/path/at/all"));
            assert!(file_rule_matches(&pat, "/tmp/file.txt"));
            assert!(file_rule_matches(&pat, "C:/Users/foo/bar.txt"));
        }
        _ => panic!("expected Read rule"),
    }
}

#[skuld::test]
fn bare_write_matches_any_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Write", home).unwrap();
    match parsed {
        ParsedRule::Write(pat) => {
            assert!(file_rule_matches(&pat, "/any/path"));
        }
        _ => panic!("expected Write rule"),
    }
}

#[skuld::test]
fn bare_edit_matches_any_path() {
    let home = "/home/test";
    let parsed = parse_single_rule("Edit", home).unwrap();
    match parsed {
        ParsedRule::Edit(pat) => {
            assert!(file_rule_matches(&pat, "/any/path"));
        }
        _ => panic!("expected Edit rule"),
    }
}

// ─── BashRule::to_rule_string ─────────────────────────────────────────────────

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
    };
    let parsed = parse_rules(&perms);
    assert_eq!(parsed.ask_bash.len(), 1);
    assert_eq!(parsed.ask_bash[0].prefix_tokens, vec!["rm"]);
    assert!(parsed.ask_bash[0].wildcard);
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
    };
    let parsed = parse_rules(&perms);
    assert_eq!(parsed.ask_read, vec![format!("{base}/**")]);
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
    };
    let parsed = parse_rules(&perms);
    assert_eq!(parsed.ask_write, vec![format!("{base}/**")]);
    assert_eq!(parsed.ask_edit, vec![format!("{base}/src/**")]);
}

// ─── Double-star (**) multi-token wildcard ────────────────────────────────────

#[skuld::test]
fn doublestar_matches_zero_tokens() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["curl", "-X", "POST", "https://example.com"])
    ));
}

#[skuld::test]
fn doublestar_matches_one_token() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["curl", "-s", "-X", "POST", "https://example.com"])
    ));
}

#[skuld::test]
fn doublestar_matches_multiple_tokens() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&[
            "curl",
            "-s",
            "-S",
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "https://example.com"
        ])
    ));
}

#[skuld::test]
fn doublestar_at_start() {
    let rule = make_rule(&["**", "-X", "POST"], true);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["curl", "-X", "POST", "https://example.com"])
    ));
}

#[skuld::test]
fn doublestar_no_match_when_suffix_differs() {
    let rule = make_rule(&["curl", "**", "-X", "POST"], true);
    assert!(!bash_rule_matches(
        &rule,
        &tokens(&["curl", "-s", "-X", "GET", "https://example.com"])
    ));
}

#[skuld::test]
fn doublestar_alone_matches_any_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(**)", home).unwrap();
    match parsed {
        ParsedRule::Bash(rule) => {
            assert!(bash_rule_matches(&rule, &tokens(&["ls"])));
            assert!(bash_rule_matches(&rule, &tokens(&["git", "status", "-s"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn trailing_doublestar_without_wildcard() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl **)", home).unwrap();
    match parsed {
        ParsedRule::Bash(rule) => {
            assert!(!rule.wildcard);
            assert_eq!(rule.prefix_tokens, vec!["curl", "**"]);
            assert!(bash_rule_matches(&rule, &tokens(&["curl"])));
            assert!(bash_rule_matches(&rule, &tokens(&["curl", "foo"])));
            assert!(bash_rule_matches(&rule, &tokens(&["curl", "foo", "bar"])));
        }
        _ => panic!("expected Bash rule"),
    }
}

#[skuld::test]
fn doublestar_parse_roundtrip() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(curl ** -X POST *)", home).unwrap();
    match parsed {
        ParsedRule::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["curl", "**", "-X", "POST"]);
            assert!(rule.wildcard);
            assert_eq!(rule.to_rule_string(), "Bash(curl ** -X POST *)");
        }
        _ => panic!("expected Bash rule"),
    }
}

// ─── Colon-wildcard format (Claude Code's native format) ─────────────────────

#[skuld::test]
fn parse_colon_wildcard_single_command() {
    let home = "/home/test";
    let parsed = parse_single_rule("Bash(grep:*)", home).unwrap();
    match parsed {
        ParsedRule::Bash(rule) => {
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
        ParsedRule::Bash(rule) => {
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
        ParsedRule::Bash(rule) => {
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
        ParsedRule::Bash(rule) => {
            assert_eq!(rule.prefix_tokens, vec!["gcc", "-print-file-name=*"]);
            assert!(rule.wildcard);
        }
        _ => panic!("expected Bash rule"),
    }
}
