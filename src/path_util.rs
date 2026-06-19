/// Default Windows CMD `PATHEXT` suffixes (Vista+), lowercased. Applied
/// unconditionally on every OS so settings files port across Windows / WSL /
/// Unix without platform-specific rewrites.
pub const PATHEXT_SUFFIXES: &[&str] = &[
    ".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc",
];

/// If `name` ends with any PATHEXT suffix (case-insensitive), return the
/// stem; otherwise return `name` unchanged.
pub fn strip_pathext_suffix(name: &str) -> &str {
    for suffix in PATHEXT_SUFFIXES {
        if name.len() >= suffix.len() {
            let tail = &name[name.len() - suffix.len()..];
            if tail.eq_ignore_ascii_case(suffix) {
                return &name[..name.len() - suffix.len()];
            }
        }
    }
    name
}

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
/// - Maps the Windows verbatim UNC prefix (`\\?\UNC\server\share` → `//?/UNC/...`)
///   back to the plain UNC form `//server/share`.
/// - Strips the Windows extended-length prefix (`\\?\` → after normalization `//?/`).
pub fn normalize_separators(path: &str) -> String {
    let s = path.replace('\\', "/");
    if let Some(rest) = s.strip_prefix("//?/UNC/") {
        return format!("//{rest}");
    }
    s.strip_prefix("//?/").unwrap_or(&s).to_string()
}

/// Compare two path strings for equality with platform filesystem semantics:
/// case-insensitive on Windows, case-sensitive elsewhere. Mirrors the
/// `#[cfg(windows)]` comparison used for command names in `filter/bash.rs`.
#[cfg(windows)]
pub fn paths_equal_for_platform(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(not(windows))]
pub fn paths_equal_for_platform(a: &str, b: &str) -> bool {
    a == b
}

/// Produce a comparison key for a path: separators normalized, and lowercased
/// on Windows (case-insensitive filesystem) but left as-is on Unix. Mirrors
/// Codex's `normalize_project_trust_lookup_key`.
pub fn normalize_path_key(path: &str) -> String {
    let normalized = normalize_separators(path);
    #[cfg(windows)]
    {
        normalized.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        normalized
    }
}

/// Glob-match a path against a pattern with platform filesystem semantics:
/// case-insensitive on Windows, case-sensitive elsewhere. Both pattern and
/// path are assumed already separator-normalized (canonical forward-slash).
pub fn glob_match_for_platform(pattern: &str, path: &str) -> bool {
    #[cfg(windows)]
    {
        glob_match::glob_match(&pattern.to_ascii_lowercase(), &path.to_ascii_lowercase())
    }
    #[cfg(not(windows))]
    {
        glob_match::glob_match(pattern, path)
    }
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
    if b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_pathext_suffix_all_variants() {
        for suffix in PATHEXT_SUFFIXES {
            let name = format!("foo{suffix}");
            assert_eq!(strip_pathext_suffix(&name), "foo", "failed on `{name}`");
        }
    }

    #[test]
    fn strip_pathext_suffix_case_insensitive() {
        assert_eq!(strip_pathext_suffix("RG.CMD"), "RG");
        assert_eq!(strip_pathext_suffix("RG.cmd"), "RG");
        assert_eq!(strip_pathext_suffix("rg.CMD"), "rg");
        assert_eq!(strip_pathext_suffix("Foo.ExE"), "Foo");
    }

    #[test]
    fn strip_pathext_suffix_no_match() {
        assert_eq!(strip_pathext_suffix("foo.py"), "foo.py");
        assert_eq!(strip_pathext_suffix("foo"), "foo");
        assert_eq!(strip_pathext_suffix(""), "");
        assert_eq!(strip_pathext_suffix("."), ".");
    }

    #[test]
    fn strip_pathext_suffix_leaves_stem_containing_dot() {
        // A program named `my.foo.exe` → stem is `my.foo`.
        assert_eq!(strip_pathext_suffix("my.foo.exe"), "my.foo");
    }

    #[test]
    fn strip_pathext_suffix_dot_ext_alone_becomes_empty() {
        // `.exe` has an empty stem; consistent with today's normalize_cmd_name(".exe") == "".
        assert_eq!(strip_pathext_suffix(".exe"), "");
    }

    #[test]
    fn strip_pathext_suffix_leaves_multichar_overlap() {
        // `.jse` should match (and strip), not get confused with `.js`.
        assert_eq!(strip_pathext_suffix("foo.jse"), "foo");
        // `.js` also matches.
        assert_eq!(strip_pathext_suffix("foo.js"), "foo");
    }

    #[test]
    fn normalize_separators_strips_verbatim_prefix() {
        assert_eq!(normalize_separators(r"\\?\C:\foo\bar"), "C:/foo/bar");
    }

    #[test]
    fn normalize_separators_maps_verbatim_unc_to_plain_unc() {
        assert_eq!(
            normalize_separators(r"\\?\UNC\server\share\dir"),
            "//server/share/dir"
        );
    }

    #[test]
    fn normalize_separators_preserves_plain_unc() {
        assert_eq!(normalize_separators(r"\\server\share"), "//server/share");
    }

    #[cfg(not(windows))]
    #[test]
    fn paths_equal_case_sensitive_on_unix() {
        assert!(paths_equal_for_platform("/a/b", "/a/b"));
        assert!(!paths_equal_for_platform("/a/b", "/A/B"));
    }

    #[cfg(windows)]
    #[test]
    fn paths_equal_case_insensitive_on_windows() {
        assert!(paths_equal_for_platform("C:/Foo", "c:/foo"));
    }

    #[cfg(not(windows))]
    #[test]
    fn normalize_path_key_preserves_case_on_unix() {
        assert_eq!(normalize_path_key("/Foo/Bar"), "/Foo/Bar");
    }

    #[cfg(windows)]
    #[test]
    fn normalize_path_key_lowercases_on_windows() {
        assert_eq!(normalize_path_key(r"C:\Foo\Bar"), "c:/foo/bar");
    }

    #[cfg(not(windows))]
    #[test]
    fn glob_match_case_sensitive_on_unix() {
        assert!(glob_match_for_platform("/a/*.txt", "/a/x.txt"));
        assert!(!glob_match_for_platform("/A/*.txt", "/a/x.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn glob_match_case_insensitive_on_windows() {
        assert!(glob_match_for_platform("C:/Repo/*.txt", "c:/repo/x.TXT"));
    }
}
