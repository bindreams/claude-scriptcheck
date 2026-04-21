use claude_scriptcheck::path_util::*;

// is_absolute =========================================================================================================

#[skuld::test]
fn unix_absolute() {
    assert!(is_absolute("/foo/bar"));
    assert!(is_absolute("/"));
}

#[skuld::test]
fn windows_drive_forward_slash() {
    assert!(is_absolute("C:/Users/foo"));
    assert!(is_absolute("c:/tmp"));
    assert!(is_absolute("D:/"));
}

#[skuld::test]
fn windows_drive_backslash() {
    assert!(is_absolute("C:\\Users\\foo"));
    assert!(is_absolute("c:\\tmp"));
}

#[skuld::test]
fn unc_path() {
    assert!(is_absolute("\\\\server\\share"));
    assert!(is_absolute("//server/share"));
}

#[skuld::test]
fn relative_paths_not_absolute() {
    assert!(!is_absolute("foo/bar"));
    assert!(!is_absolute("./foo"));
    assert!(!is_absolute("../foo"));
    assert!(!is_absolute("foo"));
    assert!(!is_absolute(""));
}

#[skuld::test]
fn bare_drive_letter_not_absolute() {
    // C: without separator is a relative path on Windows (current dir of drive)
    assert!(!is_absolute("C:"));
    assert!(!is_absolute("C:foo"));
}

// normalize_separators ================================================================================================

#[skuld::test]
fn backslashes_to_forward() {
    assert_eq!(normalize_separators("C:\\Users\\foo"), "C:/Users/foo");
}

#[skuld::test]
fn forward_slashes_unchanged() {
    assert_eq!(normalize_separators("C:/Users/foo"), "C:/Users/foo");
    assert_eq!(normalize_separators("/tmp/foo"), "/tmp/foo");
}

#[skuld::test]
fn strips_extended_length_prefix() {
    assert_eq!(
        normalize_separators("\\\\?\\C:\\Users\\foo"),
        "C:/Users/foo"
    );
}

#[skuld::test]
fn mixed_separators() {
    assert_eq!(
        normalize_separators("C:\\Users/foo\\bar"),
        "C:/Users/foo/bar"
    );
}

#[skuld::test]
fn empty_string() {
    assert_eq!(normalize_separators(""), "");
}

#[skuld::test]
fn unc_path_normalized() {
    assert_eq!(
        normalize_separators("\\\\server\\share\\file"),
        "//server/share/file"
    );
}

// is_filesystem_root ==================================================================================================

#[skuld::test]
fn unix_root_is_filesystem_root() {
    assert!(is_filesystem_root("/"));
}

#[skuld::test]
fn drive_root_forward_slash_is_filesystem_root() {
    assert!(is_filesystem_root("C:/"));
    assert!(is_filesystem_root("d:/"));
}

#[skuld::test]
fn drive_root_backslash_is_filesystem_root() {
    assert!(is_filesystem_root("C:\\"));
}

#[skuld::test]
fn unc_share_root_is_filesystem_root() {
    assert!(is_filesystem_root("//server/share"));
    assert!(is_filesystem_root("//server/share/"));
    assert!(is_filesystem_root("\\\\server\\share"));
    assert!(is_filesystem_root("\\\\server\\share\\"));
}

#[skuld::test]
fn bare_drive_letter_is_not_filesystem_root() {
    // bare "C:" is relative — not a root
    assert!(!is_filesystem_root("C:"));
}

#[skuld::test]
fn non_root_paths_are_not_filesystem_root() {
    assert!(!is_filesystem_root("/foo"));
    assert!(!is_filesystem_root("/foo/bar"));
    assert!(!is_filesystem_root("C:/Users"));
    assert!(!is_filesystem_root("//server/share/file"));
    assert!(!is_filesystem_root("//server"));
    assert!(!is_filesystem_root(""));
    assert!(!is_filesystem_root("relative/path"));
}
