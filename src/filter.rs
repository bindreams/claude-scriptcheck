//! Permission filter types.
//!
//! A `Filter` matches tool invocations against a pattern. It is verdict-agnostic:
//! where a filter appears in `.claude/settings.json` (`permissions.allow`,
//! `.deny`, or `.ask`) determines its verdict, not the filter itself.
//!
//! Filters render as `Kind(data)` (e.g. `Bash(git status *)`, `Read(/path/**)`)
//! via `to_rule_string()`, matching the rule-string format in settings files.

pub mod bash;
pub mod path;

use std::borrow::Cow;

pub use bash::BashFilter;
pub use path::{EditFilter, ReadFilter, WriteFilter};

/// A permission filter: matches a class of tool invocations.
pub trait Filter: std::fmt::Debug {
    /// The rule-string kind prefix (e.g. `"Bash"`, `"Read"`).
    fn kind(&self) -> &'static str;

    /// The rule-string payload (e.g. `"git status *"`, `"/path/**"`).
    fn data(&self) -> Cow<'_, str>;

    /// Render as `Kind(data)` — the canonical source form used in logs and settings.
    fn to_rule_string(&self) -> String {
        format!("{}({})", self.kind(), self.data())
    }
}

/// A filter over a filesystem path.
pub trait PathFilter: Filter {
    /// Returns true if `path` is covered by this filter's pattern.
    fn matches(&self, path: &str) -> bool;

    /// The canonicalized glob pattern backing this filter.
    fn pattern(&self) -> &str;
}

/// Generates `impl Filter` for a filter type.
///
/// Two forms:
/// - `impl_filter!(Ty, "Kind")` — `data()` returns `Cow::Borrowed(self.pattern())`.
///   Intended for `PathFilter` types (single-field newtypes over the pattern).
/// - `impl_filter!(Ty, "Kind", owned)` — `data()` returns `Cow::Owned(self.reconstruct_data())`.
///   Intended for types whose source form must be reconstructed (e.g. `BashFilter`).
#[macro_export]
macro_rules! impl_filter {
    ($ty:ty, $kind:literal) => {
        impl $crate::filter::Filter for $ty {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn data(&self) -> ::std::borrow::Cow<'_, str> {
                ::std::borrow::Cow::Borrowed(
                    <Self as $crate::filter::PathFilter>::pattern(self),
                )
            }
        }
    };
    ($ty:ty, $kind:literal, owned) => {
        impl $crate::filter::Filter for $ty {
            fn kind(&self) -> &'static str {
                $kind
            }
            fn data(&self) -> ::std::borrow::Cow<'_, str> {
                ::std::borrow::Cow::Owned(self.reconstruct_data())
            }
        }
    };
}

/// The verdict a filter produces when it matches.
///
/// The verdict is not a property of the filter — it is determined by which
/// JSON array the filter was parsed from (`permissions.allow` / `.deny` / `.ask`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Ask,
}

/// A verdict-bucketed collection of filters of one kind.
#[derive(Debug, Default)]
pub struct RuleSet<F> {
    pub allow: Vec<F>,
    pub deny: Vec<F>,
    pub ask: Vec<F>,
}

impl<F> RuleSet<F> {
    pub fn new() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            ask: Vec::new(),
        }
    }

    pub fn push(&mut self, verdict: Verdict, filter: F) {
        match verdict {
            Verdict::Allow => self.allow.push(filter),
            Verdict::Deny => self.deny.push(filter),
            Verdict::Ask => self.ask.push(filter),
        }
    }

    pub fn bucket(&self, verdict: Verdict) -> &[F] {
        match verdict {
            Verdict::Allow => &self.allow,
            Verdict::Deny => &self.deny,
            Verdict::Ask => &self.ask,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_filter_renders_as_kind_paren_data() {
        let f = ReadFilter::new("/tmp/file.log".to_string());
        assert_eq!(f.to_rule_string(), "Read(/tmp/file.log)");
    }

    #[test]
    fn write_filter_renders_as_kind_paren_data() {
        let f = WriteFilter::new("/tmp/out/**".to_string());
        assert_eq!(f.to_rule_string(), "Write(/tmp/out/**)");
    }

    #[test]
    fn edit_filter_renders_as_kind_paren_data() {
        let f = EditFilter::new("src/**/*.rs".to_string());
        assert_eq!(f.to_rule_string(), "Edit(src/**/*.rs)");
    }

    #[test]
    fn bash_filter_renders_as_kind_paren_data() {
        let f = BashFilter::new_wildcard(vec!["git".to_string(), "status".to_string()]);
        assert_eq!(f.to_rule_string(), "Bash(git status *)");
    }

    #[test]
    fn ruleset_push_buckets_by_verdict() {
        let mut rs: RuleSet<ReadFilter> = RuleSet::new();
        rs.push(Verdict::Allow, ReadFilter::new("/a".to_string()));
        rs.push(Verdict::Deny, ReadFilter::new("/b".to_string()));
        rs.push(Verdict::Ask, ReadFilter::new("/c".to_string()));

        assert_eq!(rs.allow.len(), 1);
        assert_eq!(rs.deny.len(), 1);
        assert_eq!(rs.ask.len(), 1);
        assert_eq!(rs.allow[0].pattern(), "/a");
        assert_eq!(rs.deny[0].pattern(), "/b");
        assert_eq!(rs.ask[0].pattern(), "/c");
    }

    #[test]
    fn ruleset_bucket_returns_correct_slice() {
        let mut rs: RuleSet<ReadFilter> = RuleSet::new();
        rs.push(Verdict::Allow, ReadFilter::new("/a".to_string()));
        rs.push(Verdict::Deny, ReadFilter::new("/b".to_string()));

        assert_eq!(rs.bucket(Verdict::Allow).len(), 1);
        assert_eq!(rs.bucket(Verdict::Deny).len(), 1);
        assert_eq!(rs.bucket(Verdict::Ask).len(), 0);
    }
}
