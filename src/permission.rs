use crate::settings::Permissions;

/// A parsed Bash command permission rule.
#[derive(Debug, Clone)]
pub struct BashRule {
    /// Tokens that must match the beginning of the command.
    pub prefix_tokens: Vec<String>,
    /// Whether a trailing `*` allows any additional arguments.
    pub wildcard: bool,
}

/// Pre-parsed permission rules, separated by category.
#[derive(Default)]
pub struct ParsedPermissions {
    pub allow_bash: Vec<BashRule>,
    pub deny_bash: Vec<BashRule>,
    pub allow_read: Vec<String>,
    pub deny_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_write: Vec<String>,
    pub allow_edit: Vec<String>,
    pub deny_edit: Vec<String>,
}

enum ParsedRule {
    Bash(BashRule),
    Read(String),
    Write(String),
    Edit(String),
}

pub fn parse_rules(perms: &Permissions) -> ParsedPermissions {
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut parsed = ParsedPermissions::default();

    for rule_str in &perms.allow {
        match parse_single_rule(rule_str, &home) {
            Some(ParsedRule::Bash(br)) => parsed.allow_bash.push(br),
            Some(ParsedRule::Read(pat)) => parsed.allow_read.push(pat),
            Some(ParsedRule::Write(pat)) => parsed.allow_write.push(pat),
            Some(ParsedRule::Edit(pat)) => parsed.allow_edit.push(pat),
            None => {}
        }
    }

    for rule_str in &perms.deny {
        match parse_single_rule(rule_str, &home) {
            Some(ParsedRule::Bash(br)) => parsed.deny_bash.push(br),
            Some(ParsedRule::Read(pat)) => parsed.deny_read.push(pat),
            Some(ParsedRule::Write(pat)) => parsed.deny_write.push(pat),
            Some(ParsedRule::Edit(pat)) => parsed.deny_edit.push(pat),
            None => {}
        }
    }

    parsed
}

fn parse_single_rule(rule: &str, home: &str) -> Option<ParsedRule> {
    if let Some(inner) = rule.strip_prefix("Bash(").and_then(|s| s.strip_suffix(')')) {
        let tokens: Vec<String> = inner.split_whitespace().map(String::from).collect();
        if tokens.is_empty() {
            return None;
        }
        // Skip "readonly" rules — handled by Claude itself
        if tokens[0] == "readonly" {
            return None;
        }
        let (prefix, wildcard) = if tokens.last().map(|s| s.as_str()) == Some("*") && tokens.len() > 1 {
            (tokens[..tokens.len() - 1].to_vec(), true)
        } else if tokens.len() == 1 && tokens[0] == "*" {
            // Bash(*) — matches everything
            (vec![], true)
        } else {
            (tokens, false)
        };
        Some(ParsedRule::Bash(BashRule {
            prefix_tokens: prefix,
            wildcard,
        }))
    } else if let Some(inner) = rule.strip_prefix("Read(").and_then(|s| s.strip_suffix(')')) {
        Some(ParsedRule::Read(inner.replace('~', home)))
    } else if let Some(inner) = rule.strip_prefix("Write(").and_then(|s| s.strip_suffix(')')) {
        Some(ParsedRule::Write(inner.replace('~', home)))
    } else if let Some(inner) = rule.strip_prefix("Edit(").and_then(|s| s.strip_suffix(')')) {
        Some(ParsedRule::Edit(inner.replace('~', home)))
    } else {
        None
    }
}

/// Check if a command (as tokens) matches a Bash rule.
pub fn bash_rule_matches(rule: &BashRule, cmd_tokens: &[String]) -> bool {
    if cmd_tokens.len() < rule.prefix_tokens.len() {
        return false;
    }
    for (rule_tok, cmd_tok) in rule.prefix_tokens.iter().zip(cmd_tokens.iter()) {
        if !token_matches(rule_tok, cmd_tok) {
            return false;
        }
    }
    if rule.wildcard {
        true
    } else {
        cmd_tokens.len() == rule.prefix_tokens.len()
    }
}

fn token_matches(pattern: &str, actual: &str) -> bool {
    if pattern.contains('*') {
        glob_match::glob_match(pattern, actual)
    } else {
        pattern == actual
    }
}

/// Check if a file path matches a file permission pattern.
pub fn file_rule_matches(pattern: &str, file_path: &str) -> bool {
    glob_match::glob_match(pattern, file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
