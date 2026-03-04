use crate::canonicalize::*;

// ─── is_wildcard_segment ──────────────────────────────────────────────────────

#[test]
fn wildcard_star() {
    assert!(is_wildcard_segment("*"));
    assert!(is_wildcard_segment("**"));
    assert!(is_wildcard_segment("foo*"));
}

#[test]
fn wildcard_question() {
    assert!(is_wildcard_segment("?"));
    assert!(is_wildcard_segment("foo?bar"));
}

#[test]
fn wildcard_bracket() {
    assert!(is_wildcard_segment("[abc]"));
    assert!(is_wildcard_segment("file[0-9]"));
}

#[test]
fn wildcard_brace() {
    assert!(is_wildcard_segment("{a,b}"));
    assert!(is_wildcard_segment("file.{rs,toml}"));
}

#[test]
fn plain_segment_not_wildcard() {
    assert!(!is_wildcard_segment("hello"));
    assert!(!is_wildcard_segment("foo.rs"));
    assert!(!is_wildcard_segment(""));
    assert!(!is_wildcard_segment(".hidden"));
}

// ─── best_effort_canonicalize ─────────────────────────────────────────────────

#[test]
fn empty_string() {
    assert_eq!(best_effort_canonicalize(""), "");
}

#[test]
fn root_path() {
    assert_eq!(best_effort_canonicalize("/"), "/");
}

#[test]
fn existing_path_no_wildcards() {
    // /tmp exists on all Unix systems
    let result = best_effort_canonicalize("/tmp");
    // Should be the canonical form (e.g., /private/tmp on macOS, /tmp on Linux)
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, expected);
}

#[test]
fn dotdot_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(dir.path()).unwrap();
    let child = base.join("child");
    std::fs::create_dir(&child).unwrap();

    let input = format!("{}/child/..", base.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, base.to_str().unwrap());
}

#[test]
fn dot_resolved() {
    let result = best_effort_canonicalize("/tmp/./.");
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, expected);
}

#[test]
fn wildcard_at_end() {
    let result = best_effort_canonicalize("/tmp/**");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/**"));
}

#[test]
fn wildcard_in_middle() {
    let result = best_effort_canonicalize("/tmp/*/foo.txt");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/*/foo.txt"));
}

#[test]
fn nonexistent_path() {
    // A clearly non-existent directory under /tmp
    let result =
        best_effort_canonicalize("/tmp/nonexistent_dir_abc123_xyz789/subdir/file.txt");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(
        result,
        format!("{canonical_tmp}/nonexistent_dir_abc123_xyz789/subdir/file.txt")
    );
}

#[test]
fn nonexistent_with_wildcard_suffix() {
    let result =
        best_effort_canonicalize("/tmp/nonexistent_abc123/**");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/nonexistent_abc123/**"));
}

#[test]
fn dotdot_before_wildcard() {
    // /tmp/nonexistent/../** → path-clean normalizes to /tmp/** → canonicalize /tmp
    let result = best_effort_canonicalize("/tmp/nonexistent/../**");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/**"));
}

#[test]
fn dotdot_in_existing_path() {
    // /tmp/../tmp should resolve to the canonical /tmp
    let result = best_effort_canonicalize("/tmp/../tmp");
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, expected);
}

#[test]
fn all_wildcard_path() {
    // No prefix to canonicalize — returned as-is after normalization
    assert_eq!(best_effort_canonicalize("**/file.txt"), "**/file.txt");
}

#[test]
fn wildcard_first_segment_absolute() {
    // /**/foo — the wildcard is the first real segment after root
    let result = best_effort_canonicalize("/**/foo");
    // The "/" root should be canonicalized, and ** is in the suffix
    let canonical_root = std::fs::canonicalize("/")
        .unwrap()
        .to_string_lossy()
        .to_string();
    // Root is "/", so result should be "/**/foo"
    assert_eq!(result, format!("{}/**/foo", canonical_root.trim_end_matches('/')));
}

#[test]
fn duplicate_slashes_normalized() {
    let result = best_effort_canonicalize("/tmp//foo");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/foo"));
}

#[test]
fn question_mark_wildcard_in_path() {
    let result = best_effort_canonicalize("/tmp/?/file");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/?/file"));
}

#[test]
fn bracket_wildcard_in_path() {
    let result = best_effort_canonicalize("/tmp/[abc]/file");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/[abc]/file"));
}

#[test]
fn brace_wildcard_in_path() {
    let result = best_effort_canonicalize("/tmp/{a,b}/file");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/{{a,b}}/file"));
}
