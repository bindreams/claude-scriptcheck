//! Directional matching between a rule pattern and an [`AccessScope`].
//!
//! Per the guiding invariant, the two directions are not the same test:
//!
//! - deny / ask ask **could** this pattern match any member of the access set?
//!   Over-approximating: a rule may fire on an access it turns out not to
//!   cover, but it may never be silently skipped.
//! - allow asks does this pattern cover **every** member? Under-approximating:
//!   a rule counts only when coverage is provable. Cases the analysis cannot
//!   prove fall through to ask, which is the correct answer under uncertainty.

use crate::canonicalize::is_wildcard_segment;
use crate::file_access::AccessScope;
use crate::path_util::{glob_match_for_platform, paths_equal_for_platform};

/// Could `pattern` match any member of `scope`? Used for deny and ask rules.
pub fn could_match(pattern: &str, scope: &AccessScope) -> bool {
    match scope {
        AccessScope::Exact(p) => glob_match_for_platform(pattern, p),
        AccessScope::Subtree(d) | AccessScope::UnboundedSubtree(d) => {
            glob_match_for_platform(pattern, d) || could_match_under(pattern, d)
        }
        AccessScope::Pattern(q) => patterns_intersect(pattern, q),
        AccessScope::Unresolved(_) => false,
    }
}

/// Does `pattern` provably cover every member of `scope`? Used for allow rules.
pub fn covers(pattern: &str, scope: &AccessScope) -> bool {
    match scope {
        AccessScope::Exact(p) => glob_match_for_platform(pattern, p),
        AccessScope::Subtree(d) => covers_subtree(pattern, d),
        // A symlink-following walk can leave the subtree entirely, so no
        // pattern bounded by the root can prove coverage.
        AccessScope::UnboundedSubtree(_) => false,
        AccessScope::Pattern(q) => covers_pattern(pattern, q),
        AccessScope::Unresolved(_) => false,
    }
}

/// Split a path or pattern into segments, dropping trailing empty ones.
///
/// `"/"` splits to `["", ""]` in Rust and `"C:/"` to `["C:", ""]`. Left alone,
/// that stray empty segment mismatches every pattern segment and the analysis
/// below "proves" a disjointness that does not hold — silently skipping every
/// deny rule for a subtree rooted at a filesystem root (`rm -rf /`).
fn segments(path: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = path.split('/').collect();
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

/// A leading `!` negates the whole pattern in `glob-match`. The segment
/// analysis cannot reason about negation, so it refuses to conclude anything.
fn is_negated(pattern: &str) -> bool {
    pattern.starts_with('!')
}

/// `[...]` classes and `{...}` alternatives can each match a `/`, so a
/// pattern's segment count understates the depth it can reach. Verified
/// against glob-match 0.2.1: `/tmp[!a]foo` matches `/tmp/foo` and
/// `/a/{b/x,c}/d` matches `/a/b/x/d`.
fn depth_is_fixed(pattern: &str) -> bool {
    !pattern.contains("**") && !pattern.contains('[') && !pattern.contains('{')
}

/// Can `pattern` match any path strictly below `dir`? Sound over-approximation:
/// `false` is returned only when the two are provably disjoint.
fn could_match_under(pattern: &str, dir: &str) -> bool {
    if is_negated(pattern) {
        return true;
    }
    let p = segments(pattern);
    let d = segments(dir);

    // Walk the pattern's leading literal segments against the directory's.
    // Every segment before the first metacharacter segment is separator-free,
    // so the positional alignment here is exact even when a later segment
    // contains a `[` or `{` that could swallow a `/`.
    let mut i = 0;
    while i < p.len() && !is_wildcard_segment(p[i]) {
        match d.get(i) {
            // The pattern names something deeper than the directory along a
            // matching literal prefix — e.g. `Deny(Read(vault/creds))` against
            // a recursive read of `vault`.
            None => return true,
            Some(seg) => {
                if !paths_equal_for_platform(p[i], seg) {
                    return false;
                }
            }
        }
        i += 1;
    }

    if i == p.len() {
        // A fully literal pattern at or above the directory. It may match the
        // directory itself (the caller tests that separately) but nothing below.
        return false;
    }

    // Stopped on a metacharacter segment. If the pattern's match depth is
    // fixed at its segment count, it cannot reach the extra segment that
    // anything strictly below the directory must have.
    if depth_is_fixed(pattern) && p.len() <= d.len() {
        return false;
    }
    true
}

/// `dir` and every ancestor up to the filesystem root.
fn ancestors(dir: &str) -> Vec<String> {
    let segs = segments(dir);
    let mut out = Vec::new();
    for end in (1..=segs.len()).rev() {
        let joined = segs[..end].join("/");
        // The root's segments are `[""]`, which joins to the empty string.
        out.push(if joined.is_empty() {
            "/".to_string()
        } else {
            joined
        });
    }
    out
}

/// The prefix of a `X/**` pattern, if it has that shape. `"**"` covers
/// everything; `"/**"` has the filesystem root as its prefix.
fn globstar_prefix(pattern: &str) -> Option<&str> {
    if pattern == "**" {
        return Some("**");
    }
    let prefix = pattern.strip_suffix("/**")?;
    Some(if prefix.is_empty() { "/" } else { prefix })
}

/// Does `pattern` provably cover `dir` and everything beneath it?
fn covers_subtree(pattern: &str, dir: &str) -> bool {
    if is_negated(pattern) {
        return false;
    }
    let Some(prefix) = globstar_prefix(pattern) else {
        return false;
    };

    // Below the directory: the pattern's prefix must match the directory or
    // one of its ancestors, so that `**` absorbs the rest of every path under it.
    let covers_below = prefix == "**"
        || ancestors(dir)
            .iter()
            .any(|a| glob_match_for_platform(prefix, a));
    if !covers_below {
        return false;
    }

    // The directory itself: an allow pattern `X/**` whose `X` matches the
    // subtree root counts as covering that root, so `Read(vault/**)` permits
    // `grep -r vault`. Deliberately not generalized to `Exact` accesses.
    glob_match_for_platform(pattern, dir) || glob_match_for_platform(prefix, dir)
}

/// Could two patterns match a common path? Over-approximating: `false` only
/// when they are provably disjoint.
fn patterns_intersect(a: &str, b: &str) -> bool {
    if is_negated(a) || is_negated(b) {
        return true;
    }
    let x = segments(a);
    let y = segments(b);

    // A `**` segment consumes any number of segments, so nothing past it lines
    // up positionally — stop there and refuse to conclude disjointness.
    for (sx, sy) in x.iter().zip(y.iter()) {
        if *sx == "**" || *sy == "**" {
            return true;
        }
        if !is_wildcard_segment(sx) && !is_wildcard_segment(sy) && !paths_equal_for_platform(sx, sy)
        {
            return false;
        }
    }

    if depth_is_fixed(a) && depth_is_fixed(b) && x.len() != y.len() {
        return false;
    }
    true
}

/// Does `pattern` provably cover every path `query` can match?
fn covers_pattern(pattern: &str, query: &str) -> bool {
    if is_negated(pattern) || is_negated(query) {
        return false;
    }
    if pattern == query {
        return true;
    }
    let Some(prefix) = globstar_prefix(pattern) else {
        return false;
    };
    if prefix == "**" {
        return true;
    }
    // Only a literal prefix can be compared segment-for-segment; anything else
    // is refused rather than guessed.
    let p = segments(prefix);
    if p.iter().any(|s| is_wildcard_segment(s)) {
        return false;
    }
    let q = segments(query);
    if q.len() <= p.len() {
        return false;
    }
    p.iter()
        .zip(q.iter())
        .all(|(a, b)| !is_wildcard_segment(b) && paths_equal_for_platform(a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(p: &str) -> AccessScope {
        AccessScope::Exact(p.to_string())
    }
    fn subtree(p: &str) -> AccessScope {
        AccessScope::Subtree(p.to_string())
    }
    fn unbounded(p: &str) -> AccessScope {
        AccessScope::UnboundedSubtree(p.to_string())
    }
    fn pattern(p: &str) -> AccessScope {
        AccessScope::Pattern(p.to_string())
    }

    #[test]
    fn deny_rule_under_root_could_match() {
        assert!(could_match("/repro/vault/**", &subtree("/repro/vault")));
        assert!(could_match("/repro/vault/**", &subtree("/repro")));
    }

    #[test]
    fn descendant_literal_pattern_is_reachable() {
        assert!(could_match("/vault/creds", &subtree("/vault")));
        assert!(could_match("/vault/secrets/**", &subtree("/vault")));
    }

    #[test]
    fn filesystem_root_subtree_reaches_everything() {
        assert!(could_match("/etc/**", &subtree("/")));
        assert!(could_match("/repro/vault/**", &subtree("/")));
        assert!(could_match("C:/etc/**", &subtree("C:/")));
    }

    #[test]
    fn sibling_directory_is_disjoint() {
        assert!(!could_match("/repro/vault/**", &subtree("/other")));
    }

    #[test]
    fn fixed_depth_pattern_does_not_reach_into_subtree() {
        assert!(!could_match("/tmp/*.log", &subtree("/tmp/foo")));
    }

    #[test]
    fn globstar_pattern_reaches_any_root() {
        assert!(could_match("/**/secrets", &subtree("/tmp/foo")));
    }

    #[test]
    fn literal_pattern_at_or_above_root_does_not_reach_below() {
        assert!(!could_match("/tmp", &subtree("/tmp/foo")));
        // The root itself still matches via the `glob_match` disjunct.
        assert!(could_match("/tmp/foo", &subtree("/tmp/foo")));
        assert!(!could_match_under("/tmp/foo", "/tmp/foo"));
    }

    #[test]
    fn bracket_class_disables_depth_refinement() {
        // `[!a]` can match `/`, so this pattern really can match `/tmp/vault`.
        assert!(could_match("/tmp[!a]vault", &subtree("/tmp")));
    }

    #[test]
    fn brace_pattern_disables_depth_refinement() {
        assert!(could_match("/tmp/{a,b/c}", &subtree("/tmp/x")));
    }

    #[test]
    fn negated_pattern_is_conservative() {
        assert!(could_match("!/a/b", &subtree("/zzz")));
        assert!(!covers("!/a/b", &subtree("/a/b")));
    }

    #[test]
    fn subtree_root_covered_by_globstar_rule() {
        assert!(covers("/vault/**", &subtree("/vault")));
        // An Exact access to the root is untouched by the X/** rule.
        assert!(!covers("/vault/**", &exact("/vault")));
    }

    #[test]
    fn ancestor_globstar_rule_covers_subtree() {
        assert!(covers("/a/**", &subtree("/a/b")));
        assert!(covers("/a/**", &subtree("/a/b/c")));
    }

    #[test]
    fn descendant_rule_does_not_cover_ancestor_subtree() {
        assert!(!covers("/a/b/**", &subtree("/a")));
    }

    #[test]
    fn single_star_rule_does_not_cover_subtree() {
        assert!(!covers("/a/*", &subtree("/a/b")));
    }

    #[test]
    fn exotic_globstar_rule_does_not_cover_subtree() {
        assert!(!covers("/a/b/**/*", &subtree("/a/b")));
    }

    #[test]
    fn everything_rule_covers_subtree() {
        assert!(covers("**", &subtree("/a/b")));
        assert!(covers("/**", &subtree("/")));
    }

    #[test]
    fn unbounded_subtree_denies_like_subtree_but_is_never_covered() {
        assert!(could_match("/vault/**", &unbounded("/vault")));
        assert!(could_match("/vault/creds", &unbounded("/vault")));
        assert!(!covers("**", &unbounded("/vault")));
        assert!(!covers("/vault/**", &unbounded("/vault")));
    }

    #[test]
    fn unresolved_never_matches_and_never_satisfies() {
        let u = AccessScope::Unresolved("$FOO".to_string());
        assert!(!could_match("**", &u));
        assert!(!covers("**", &u));
    }

    #[test]
    fn pattern_scope_intersects_and_covers() {
        assert!(could_match("/home/*/secrets", &pattern("/home/*/secrets")));
        assert!(!could_match("/etc/**", &pattern("/home/*/secrets")));
        assert!(could_match("/tmp[!a]x", &pattern("/tmp/x/y")));
        assert!(covers("/home/**", &pattern("/home/a/*")));
        assert!(!covers("/home/*", &pattern("/home/a/*")));
    }

    #[test]
    fn globstar_stops_positional_pattern_comparison() {
        // Both patterns match /a/x/y/c/d, so they must not be called disjoint.
        assert!(patterns_intersect("/a/**/c/d", "/a/x/y/c/*"));
        assert!(patterns_intersect("/a/x/y/c/*", "/a/**/c/d"));
        assert!(could_match("/a/**/c/d", &pattern("/a/x/y/c/*")));
        // A literal mismatch before any `**` is still provable.
        assert!(!patterns_intersect("/a/**/c/d", "/b/x/**"));
    }

    #[test]
    fn exact_scope_is_todays_behavior() {
        for (pat, path) in [
            ("/tmp/**", "/tmp/a/b"),
            ("/tmp/*.log", "/tmp/x.log"),
            ("/tmp/a", "/tmp/b"),
            ("**", "/anything"),
        ] {
            let expected = glob_match_for_platform(pat, path);
            assert_eq!(could_match(pat, &exact(path)), expected, "{pat} vs {path}");
            assert_eq!(covers(pat, &exact(path)), expected, "{pat} vs {path}");
        }
    }
}
