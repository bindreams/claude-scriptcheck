use std::path::Path;

use claude_scriptcheck::canonicalize::*;
use claude_scriptcheck::path_util;

/// Canonical temp directory path with normalized separators.
fn canonical_temp() -> String {
    path_util::normalize_separators(
        &std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .to_string_lossy(),
    )
}

/// Filesystem-canonical path with normalized separators.
fn canonical(path: &str) -> String {
    path_util::normalize_separators(&std::fs::canonicalize(path).unwrap().to_string_lossy())
}

// is_wildcard_segment =================================================================================================

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

// best_effort_canonicalize ============================================================================================

#[skuld::test]
fn empty_string() {
    assert_eq!(best_effort_canonicalize(""), "");
}

#[skuld::test]
fn root_path() {
    // On Unix: "/" → "/". On Windows: "/" may resolve differently.
    let result = best_effort_canonicalize("/");
    #[cfg(unix)]
    assert_eq!(result, "/");
    #[cfg(windows)]
    assert!(result == "/" || path_util::is_absolute(&result));
}

#[skuld::test]
fn existing_path_no_wildcards(#[fixture(temp_dir)] dir: &Path) {
    let expected = canonical(dir.to_str().unwrap());
    let result = best_effort_canonicalize(dir.to_str().unwrap());
    assert_eq!(result, expected);
}

#[skuld::test]
fn dotdot_resolved(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let child = Path::new(dir).join("child");
    std::fs::create_dir(&child).unwrap();

    let input = format!("{base}/child/..");
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, base);
}

#[skuld::test]
fn dot_resolved(#[fixture(temp_dir)] dir: &Path) {
    let expected = canonical(dir.to_str().unwrap());
    let input = format!("{}/./.", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, expected);
}

#[skuld::test]
fn wildcard_at_end(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/**", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/**"));
}

#[skuld::test]
fn wildcard_in_middle(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/*/foo.txt", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/*/foo.txt"));
}

#[skuld::test]
fn nonexistent_path(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/nonexistent_dir_abc123/subdir/file.txt", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(
        result,
        format!("{base}/nonexistent_dir_abc123/subdir/file.txt")
    );
}

#[skuld::test]
fn nonexistent_with_wildcard_suffix(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/nonexistent_abc123/**", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/nonexistent_abc123/**"));
}

#[skuld::test]
fn dotdot_before_wildcard(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/nonexistent/../**", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/**"));
}

#[skuld::test]
fn dotdot_in_existing_path() {
    let tmp = canonical_temp();
    let input = format!(
        "{tmp}/../{}",
        Path::new(&tmp).file_name().unwrap().to_str().unwrap()
    );
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, tmp);
}

#[skuld::test]
fn all_wildcard_path() {
    assert_eq!(best_effort_canonicalize("**/file.txt"), "**/file.txt");
}

#[skuld::test]
fn wildcard_first_segment_absolute() {
    // When the first real segment is a wildcard, canonicalize can't resolve anything
    // beyond the root — the result keeps the logical normalized form.
    let result = best_effort_canonicalize("/**/foo");
    assert_eq!(result, "/**/foo");
}

#[skuld::test]
fn duplicate_slashes_normalized(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    std::fs::create_dir(Path::new(dir).join("foo")).ok();
    let input = format!("{}//foo", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/foo"));
}

#[skuld::test]
fn question_mark_wildcard_in_path(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/?/file", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/?/file"));
}

#[skuld::test]
fn bracket_wildcard_in_path(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/[abc]/file", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/[abc]/file"));
}

#[skuld::test]
fn brace_wildcard_in_path(#[fixture(temp_dir)] dir: &Path) {
    let base = canonical(dir.to_str().unwrap());
    let input = format!("{}/{{a,b}}/file", dir.display());
    let result = best_effort_canonicalize(&input);
    assert_eq!(result, format!("{base}/{{a,b}}/file"));
}
