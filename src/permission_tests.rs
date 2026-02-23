use crate::permission::*;
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

#[test]
fn exact_match() {
    let rule = make_rule(&["git", "status"], false);
    assert!(bash_rule_matches(&rule, &tokens(&["git", "status"])));
}

#[test]
fn exact_no_extra_args() {
    let rule = make_rule(&["git", "status"], false);
    assert!(!bash_rule_matches(&rule, &tokens(&["git", "status", "-s"])));
}

#[test]
fn wildcard_with_extra_args() {
    let rule = make_rule(&["git", "status"], true);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["git", "status", "-s"])
    ));
}

#[test]
fn wildcard_exact_prefix() {
    let rule = make_rule(&["git", "status"], true);
    assert!(bash_rule_matches(&rule, &tokens(&["git", "status"])));
}

#[test]
fn wrong_prefix() {
    let rule = make_rule(&["git", "status"], true);
    assert!(!bash_rule_matches(&rule, &tokens(&["git", "commit"])));
}

#[test]
fn single_command_no_wildcard() {
    let rule = make_rule(&["ls"], false);
    assert!(bash_rule_matches(&rule, &tokens(&["ls"])));
    assert!(!bash_rule_matches(&rule, &tokens(&["ls", "-la"])));
}

#[test]
fn single_command_with_wildcard() {
    let rule = make_rule(&["ls"], true);
    assert!(bash_rule_matches(&rule, &tokens(&["ls"])));
    assert!(bash_rule_matches(&rule, &tokens(&["ls", "-la", "/tmp"])));
}

#[test]
fn token_with_glob() {
    let rule = make_rule(&["gcc", "-print-file-name=*"], false);
    assert!(bash_rule_matches(
        &rule,
        &tokens(&["gcc", "-print-file-name=libgcc.a"])
    ));
}

#[test]
fn too_short_command() {
    let rule = make_rule(&["git", "status"], false);
    assert!(!bash_rule_matches(&rule, &tokens(&["git"])));
}

#[test]
fn file_pattern_match() {
    assert!(file_rule_matches("/tmp/claude/**", "/tmp/claude/foo/bar.txt"));
}

#[test]
fn file_pattern_no_match() {
    assert!(!file_rule_matches("/tmp/claude/**", "/home/user/file.txt"));
}

#[test]
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

#[test]
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

#[test]
fn parse_read_rule() {
    let home = "/home/test";
    let parsed = parse_single_rule("Read(~/src/**)", home).unwrap();
    match parsed {
        ParsedRule::Read(pat) => assert_eq!(pat, "/home/test/src/**"),
        _ => panic!("expected Read rule"),
    }
}

#[test]
fn parse_write_rule() {
    let home = "/home/test";
    let parsed = parse_single_rule("Write(/tmp/claude/**)", home).unwrap();
    match parsed {
        ParsedRule::Write(pat) => assert_eq!(pat, "/tmp/claude/**"),
        _ => panic!("expected Write rule"),
    }
}

#[test]
fn parse_readonly_skipped() {
    let home = "/home/test";
    assert!(parse_single_rule("Bash(readonly)", home).is_none());
    assert!(parse_single_rule("Bash(readonly *)", home).is_none());
}

#[test]
fn parse_irrelevant_rule_skipped() {
    let home = "/home/test";
    assert!(parse_single_rule("WebSearch", home).is_none());
    assert!(parse_single_rule("mcp__Glean__*", home).is_none());
}
