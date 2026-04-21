//! `BashFilter` — token-based glob filter for Bash commands.
//!
//! Moved verbatim from the prior `permission::BashRule` with the rule-matching
//! helpers (`match_tokens`, `token_matches`). `matches` takes command tokens
//! (the command name followed by its arguments).

use crate::impl_filter;

/// A Bash command filter.
#[derive(Debug, Clone)]
pub struct BashFilter {
    /// Tokens that must match the beginning of the command.
    pub prefix_tokens: Vec<String>,
    /// Whether a trailing `*` allows any additional arguments.
    pub wildcard: bool,
}

impl BashFilter {
    /// Filter with fixed prefix tokens and no trailing wildcard (exact-arity match).
    pub fn new(prefix_tokens: Vec<String>) -> Self {
        Self {
            prefix_tokens,
            wildcard: false,
        }
    }

    /// Filter with prefix tokens and a trailing `*` (matches any additional args).
    pub fn new_wildcard(prefix_tokens: Vec<String>) -> Self {
        Self {
            prefix_tokens,
            wildcard: true,
        }
    }

    /// Matches any command (bare `Bash(*)`).
    pub fn wildcard_all() -> Self {
        Self {
            prefix_tokens: Vec::new(),
            wildcard: true,
        }
    }

    /// Returns true if this filter matches the given command tokens.
    pub fn matches(&self, cmd_tokens: &[String]) -> bool {
        match_tokens(&self.prefix_tokens, cmd_tokens, self.wildcard)
    }

    /// Reconstruct the rule-string payload — e.g. `git status *` or `*`.
    pub fn reconstruct_data(&self) -> String {
        if self.prefix_tokens.is_empty() && self.wildcard {
            "*".to_string()
        } else if self.wildcard {
            format!("{} *", self.prefix_tokens.join(" "))
        } else {
            self.prefix_tokens.join(" ")
        }
    }
}

impl_filter!(BashFilter, "Bash", owned);

fn match_tokens(rule_tokens: &[String], cmd_tokens: &[String], wildcard: bool) -> bool {
    if rule_tokens.is_empty() {
        return if wildcard {
            true
        } else {
            cmd_tokens.is_empty()
        };
    }
    if rule_tokens[0] == "**" {
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
        true
    } else if pattern.contains('*') {
        glob_match::glob_match(pattern, actual)
    } else {
        pattern == actual
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;

    fn toks(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn exact_prefix_no_wildcard_matches_exact() {
        let f = BashFilter::new(toks("git status"));
        assert!(f.matches(&toks("git status")));
        assert!(!f.matches(&toks("git status -s")));
    }

    #[test]
    fn prefix_with_wildcard_matches_extra_args() {
        let f = BashFilter::new_wildcard(toks("git status"));
        assert!(f.matches(&toks("git status")));
        assert!(f.matches(&toks("git status -s")));
        assert!(!f.matches(&toks("git log")));
    }

    #[test]
    fn wildcard_all_matches_anything() {
        let f = BashFilter::wildcard_all();
        assert!(f.matches(&toks("anything at all")));
        assert!(f.matches(&toks("x")));
        assert!(f.matches(&[]));
    }

    #[test]
    fn bare_star_token_matches_any_single_token_including_slash() {
        let f = BashFilter::new(vec!["git".into(), "-C".into(), "*".into(), "status".into()]);
        assert!(f.matches(&toks("git -C some/nested/path status")));
    }

    #[test]
    fn reconstruct_data_shapes() {
        assert_eq!(BashFilter::wildcard_all().reconstruct_data(), "*");
        assert_eq!(
            BashFilter::new_wildcard(toks("rm -rf")).reconstruct_data(),
            "rm -rf *"
        );
        assert_eq!(
            BashFilter::new(toks("git status")).reconstruct_data(),
            "git status"
        );
    }

    #[test]
    fn rule_string_for_bash_filter() {
        assert_eq!(BashFilter::wildcard_all().to_rule_string(), "Bash(*)");
        assert_eq!(
            BashFilter::new_wildcard(toks("ls")).to_rule_string(),
            "Bash(ls *)"
        );
    }
}
