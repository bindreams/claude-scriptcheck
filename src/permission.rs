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
    pub ask_bash: Vec<BashRule>,
    pub allow_read: Vec<String>,
    pub deny_read: Vec<String>,
    pub ask_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_write: Vec<String>,
    pub ask_write: Vec<String>,
    pub allow_edit: Vec<String>,
    pub deny_edit: Vec<String>,
    pub ask_edit: Vec<String>,
}

pub(crate) enum ParsedRule {
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

    for rule_str in &perms.ask {
        match parse_single_rule(rule_str, &home) {
            Some(ParsedRule::Bash(br)) => parsed.ask_bash.push(br),
            Some(ParsedRule::Read(pat)) => parsed.ask_read.push(pat),
            Some(ParsedRule::Write(pat)) => parsed.ask_write.push(pat),
            Some(ParsedRule::Edit(pat)) => parsed.ask_edit.push(pat),
            None => {}
        }
    }

    parsed
}

pub(crate) fn parse_single_rule(rule: &str, home: &str) -> Option<ParsedRule> {
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
        Some(ParsedRule::Read(crate::canonicalize::best_effort_canonicalize(&inner.replace('~', home))))
    } else if let Some(inner) = rule.strip_prefix("Write(").and_then(|s| s.strip_suffix(')')) {
        Some(ParsedRule::Write(crate::canonicalize::best_effort_canonicalize(&inner.replace('~', home))))
    } else if let Some(inner) = rule.strip_prefix("Edit(").and_then(|s| s.strip_suffix(')')) {
        Some(ParsedRule::Edit(crate::canonicalize::best_effort_canonicalize(&inner.replace('~', home))))
    } else {
        None
    }
}

impl BashRule {
    /// Reconstruct a human-readable rule string, e.g. `Bash(git status *)`.
    pub fn to_rule_string(&self) -> String {
        if self.prefix_tokens.is_empty() && self.wildcard {
            "Bash(*)".to_string()
        } else if self.wildcard {
            format!("Bash({} *)", self.prefix_tokens.join(" "))
        } else {
            format!("Bash({})", self.prefix_tokens.join(" "))
        }
    }
}

/// Check if a command (as tokens) matches a Bash rule.
pub fn bash_rule_matches(rule: &BashRule, cmd_tokens: &[String]) -> bool {
    match_tokens(&rule.prefix_tokens, cmd_tokens, rule.wildcard)
}

/// Recursive token matcher that supports `**` (matches zero or more tokens).
fn match_tokens(rule_tokens: &[String], cmd_tokens: &[String], wildcard: bool) -> bool {
    if rule_tokens.is_empty() {
        return if wildcard { true } else { cmd_tokens.is_empty() };
    }
    if rule_tokens[0] == "**" {
        // ** matches 0 or more command tokens
        for skip in 0..=cmd_tokens.len() {
            if match_tokens(&rule_tokens[1..], &cmd_tokens[skip..], wildcard) {
                return true;
            }
        }
        return false;
    }
    if cmd_tokens.is_empty() {
        return false;
    }
    if !token_matches(&rule_tokens[0], &cmd_tokens[0]) {
        return false;
    }
    match_tokens(&rule_tokens[1..], &cmd_tokens[1..], wildcard)
}

fn token_matches(pattern: &str, actual: &str) -> bool {
    if pattern == "*" {
        // Bare `*` matches any single token, including paths with `/`.
        // (glob_match's `*` excludes `/`, which breaks rules like `git -C * status`.)
        true
    } else if pattern.contains('*') {
        glob_match::glob_match(pattern, actual)
    } else {
        pattern == actual
    }
}

/// Check if a file path matches a file permission pattern.
pub fn file_rule_matches(pattern: &str, file_path: &str) -> bool {
    glob_match::glob_match(pattern, file_path)
}
