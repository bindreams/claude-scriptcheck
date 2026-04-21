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

/// Returns true if `path` refers to an entire filesystem root.
///
/// Such paths must not be used as workspace directories — injecting
/// `Write(<root>/**)` would grant the equivalent of a bare `Write(**)`, letting
/// any path on the filesystem slip through `acceptEdits` without user review.
///
/// Recognized roots:
/// - Unix root: `/`
/// - Windows drive root: `C:/`, `C:\` (with trailing separator — bare `C:` is
///   relative and is NOT a root)
/// - UNC share root: `//server/share` (with or without trailing `/`), and the
///   equivalent `\\server\share` backslash form.
pub fn is_filesystem_root(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    // Drive root: "C:/" or "C:\" (three bytes, trailing separator).
    let b = path.as_bytes();
    if b.len() == 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'/' || b[2] == b'\\')
    {
        return true;
    }
    // UNC share root: after normalization, `//server/share` with optional trailing `/`.
    let normalized = normalize_separators(path);
    if let Some(rest) = normalized.strip_prefix("//") {
        let rest = rest.trim_end_matches('/');
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            return true;
        }
    }
    false
}
