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
}
