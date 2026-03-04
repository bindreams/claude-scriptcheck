use std::path::Path;

use claude_scriptcheck::canonicalize::*;

// ─── is_wildcard_segment ──────────────────────────────────────────────────────

#[skuld::test]
fn wildcard_star() {
    assert!(is_wildcard_segment("*"));
    assert!(is_wildcard_segment("**"));
    assert!(is_wildcard_segment("foo*"));
}

#[skuld::test]
fn wildcard_question() {
    assert!(is_wildcard_segment("?"));
    assert!(is_wildcard_segment("foo?bar"));
}

#[skuld::test]
fn wildcard_bracket() {
    assert!(is_wildcard_segment("[abc]"));
    assert!(is_wildcard_segment("file[0-9]"));
}

#[skuld::test]
fn wildcard_brace() {
    assert!(is_wildcard_segment("{a,b}"));
    assert!(is_wildcard_segment("file.{rs,toml}"));
}

#[skuld::test]
fn plain_segment_not_wildcard() {
    assert!(!is_wildcard_segment("hello"));
    assert!(!is_wildcard_segment("foo.rs"));
    assert!(!is_wildcard_segment(""));
    assert!(!is_wildcard_segment(".hidden"));
}

// ─── best_effort_canonicalize ─────────────────────────────────────────────────

#[skuld::test]
fn empty_string() {
    assert_eq!(best_effort_canonicalize(""), "");
}

#[skuld::test]
fn root_path() {
    assert_eq!(best_effort_canonicalize("/"), "/");
}

#[skuld::test]
fn existing_path_no_wildcards() {
    let result = best_effort_canonicalize("/tmp");
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, expected);
}

#[skuld::test]
fn dotdot_resolved(#[fixture(temp_dir)] dir: &Path) {
    let base = std::fs::canonicalize(dir).unwrap();
    let child = base.join("child");
    std::fs::create_dir(&child).unwrap();

    let input = format!("{}/child/..", base.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, base.to_str().unwrap());
}

#[skuld::test]
fn dot_resolved() {
    let result = best_effort_canonicalize("/tmp/./.");
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, expected);
}

#[skuld::test]
fn wildcard_at_end() {
    let result = best_effort_canonicalize("/tmp/**");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/**"));
}

#[skuld::test]
fn wildcard_in_middle() {
    let result = best_effort_canonicalize("/tmp/*/foo.txt");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/*/foo.txt"));
}

#[skuld::test]
fn nonexistent_path() {
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

#[skuld::test]
fn nonexistent_with_wildcard_suffix() {
    let result =
        best_effort_canonicalize("/tmp/nonexistent_abc123/**");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/nonexistent_abc123/**"));
}

#[skuld::test]
fn dotdot_before_wildcard() {
    let result = best_effort_canonicalize("/tmp/nonexistent/../**");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/**"));
}

#[skuld::test]
fn dotdot_in_existing_path() {
    let result = best_effort_canonicalize("/tmp/../tmp");
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, expected);
}

#[skuld::test]
fn all_wildcard_path() {
    assert_eq!(best_effort_canonicalize("**/file.txt"), "**/file.txt");
}

#[skuld::test]
fn wildcard_first_segment_absolute() {
    let result = best_effort_canonicalize("/**/foo");
    let canonical_root = std::fs::canonicalize("/")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{}/**/foo", canonical_root.trim_end_matches('/')));
}

#[skuld::test]
fn duplicate_slashes_normalized() {
    let result = best_effort_canonicalize("/tmp//foo");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/foo"));
}

#[skuld::test]
fn question_mark_wildcard_in_path() {
    let result = best_effort_canonicalize("/tmp/?/file");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/?/file"));
}

#[skuld::test]
fn bracket_wildcard_in_path() {
    let result = best_effort_canonicalize("/tmp/[abc]/file");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/[abc]/file"));
}

#[skuld::test]
fn brace_wildcard_in_path() {
    let result = best_effort_canonicalize("/tmp/{a,b}/file");
    let canonical_tmp = std::fs::canonicalize("/tmp")
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert_eq!(result, format!("{canonical_tmp}/{{a,b}}/file"));
}
