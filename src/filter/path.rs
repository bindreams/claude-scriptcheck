//! `ReadFilter`, `WriteFilter`, `EditFilter` — path-based glob filters.
//!
//! Single-field newtypes over a canonical glob pattern string. The constructors
//! assert the pattern is in canonical (forward-slash) form so `matches()` can
//! skip runtime separator normalization.

use crate::impl_filter;
use crate::path_util;

use super::PathFilter;

#[derive(Debug, Clone)]
pub struct ReadFilter(String);

#[derive(Debug, Clone)]
pub struct WriteFilter(String);

#[derive(Debug, Clone)]
pub struct EditFilter(String);

impl ReadFilter {
    pub fn new(pattern: String) -> Self {
        debug_assert!(
            pattern == path_util::normalize_separators(&pattern),
            "ReadFilter pattern must be canonical (forward-slash): {pattern:?}"
        );
        Self(pattern)
    }
}

impl WriteFilter {
    pub fn new(pattern: String) -> Self {
        debug_assert!(
            pattern == path_util::normalize_separators(&pattern),
            "WriteFilter pattern must be canonical (forward-slash): {pattern:?}"
        );
        Self(pattern)
    }
}

impl EditFilter {
    pub fn new(pattern: String) -> Self {
        debug_assert!(
            pattern == path_util::normalize_separators(&pattern),
            "EditFilter pattern must be canonical (forward-slash): {pattern:?}"
        );
        Self(pattern)
    }
}

impl PathFilter for ReadFilter {
    fn matches(&self, path: &str) -> bool {
        path_util::glob_match_for_platform(&self.0, path)
    }
    fn pattern(&self) -> &str {
        &self.0
    }
}

impl PathFilter for WriteFilter {
    fn matches(&self, path: &str) -> bool {
        path_util::glob_match_for_platform(&self.0, path)
    }
    fn pattern(&self) -> &str {
        &self.0
    }
}

impl PathFilter for EditFilter {
    fn matches(&self, path: &str) -> bool {
        path_util::glob_match_for_platform(&self.0, path)
    }
    fn pattern(&self) -> &str {
        &self.0
    }
}

impl_filter!(ReadFilter, "Read");
impl_filter!(WriteFilter, "Write");
impl_filter!(EditFilter, "Edit");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;

    #[test]
    fn read_filter_matches_literal() {
        let f = ReadFilter::new("/tmp/file.log".into());
        assert!(f.matches("/tmp/file.log"));
        assert!(!f.matches("/tmp/other.log"));
    }

    #[test]
    fn write_filter_matches_glob() {
        let f = WriteFilter::new("/tmp/out/**".into());
        assert!(f.matches("/tmp/out/a.txt"));
        assert!(f.matches("/tmp/out/nested/b.txt"));
        assert!(!f.matches("/tmp/other/a.txt"));
    }

    #[test]
    fn edit_filter_matches_extension_glob() {
        let f = EditFilter::new("src/**/*.rs".into());
        assert!(f.matches("src/foo.rs"));
        assert!(f.matches("src/deep/nested/bar.rs"));
        assert!(!f.matches("src/foo.md"));
    }

    #[test]
    fn pattern_returns_backing_string() {
        let f = ReadFilter::new("/a/b/**".into());
        assert_eq!(f.pattern(), "/a/b/**");
    }

    #[test]
    fn rule_string_renders_kind_prefix() {
        assert_eq!(ReadFilter::new("/x".into()).to_rule_string(), "Read(/x)");
        assert_eq!(WriteFilter::new("/y".into()).to_rule_string(), "Write(/y)");
        assert_eq!(EditFilter::new("/z".into()).to_rule_string(), "Edit(/z)");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "pattern must be canonical")]
    fn debug_assert_fires_on_backslash_pattern() {
        let _ = ReadFilter::new("C:\\Users\\alice".into());
    }
}
