/// Returns true if `path` is an absolute path on any platform.
///
/// Handles Unix (`/foo`), Windows drive-letter (`C:/foo`, `C:\foo`),
/// and UNC paths (`\\server\share`, `//server/share`).
pub fn is_absolute(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') {
        return true;
    }
    // Drive letter: C:/ or C:\.
    let b = path.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

/// Normalize path separators for internal use.
///
/// - Replaces all `\` with `/`.
/// - Strips the Windows extended-length prefix (`\\?\` → after normalization `//?/`).
pub fn normalize_separators(path: &str) -> String {
    let s = path.replace('\\', "/");
    s.strip_prefix("//?/").unwrap_or(&s).to_string()
}
