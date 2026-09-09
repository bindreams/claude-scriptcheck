/// Kinds of file access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

/// The set of paths one file access touches.
///
/// Rule matching is directional over this set: deny/ask ask whether a pattern
/// *could* match any member (over-approximating), allow asks whether it covers
/// *every* member (under-approximating). See `filter::scope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessScope {
    /// One concrete path.
    Exact(String),
    /// A path and everything beneath it.
    Subtree(String),
    /// A subtree walked with symlinks followed, so the access can also reach
    /// whatever a symlink under the root points at. Deny/ask behave as for
    /// `Subtree`; no allow rule can prove coverage, so it always prompts.
    UnboundedSubtree(String),
    /// A glob pattern from a globbed word (`cat /home/*/secrets`).
    ///
    /// **Not dead code.** Nothing constructs this variant on its own: shell
    /// words are resolved by the caller, and the word resolver that can tell a
    /// globbed word from a literal one is the unresolved-path work (#45, #48,
    /// #49), which populates it. Its matching is implemented and tested here so
    /// that work has a scope to emit — do not remove it as unused.
    Pattern(String),
    /// A path-shaped word whose value could not be determined. Matches no rule
    /// and satisfies none, so it always prompts.
    ///
    /// **Not dead code**, for the same reason as `Pattern`: the unresolved-path
    /// work (#45, #48, #49) is what constructs it.
    Unresolved(String),
}

impl AccessScope {
    /// The inner string: a path for `Exact`/`Subtree`/`UnboundedSubtree`, a
    /// pattern for `Pattern`, a reason for `Unresolved`.
    pub fn path(&self) -> &str {
        match self {
            Self::Exact(p)
            | Self::Subtree(p)
            | Self::UnboundedSubtree(p)
            | Self::Pattern(p)
            | Self::Unresolved(p) => p,
        }
    }

    /// The user-facing form, used for missing-rule suggestions and deny reasons.
    pub fn display(&self) -> String {
        match self {
            Self::Exact(p) | Self::Pattern(p) => p.clone(),
            // Strip a trailing separator first: a subtree rooted at `/` would
            // otherwise render as `//**`, which reads as a UNC path.
            Self::Subtree(d) => format!("{}/**", d.trim_end_matches('/')),
            Self::UnboundedSubtree(d) => format!("{}/**+symlinks", d.trim_end_matches('/')),
            Self::Unresolved(reason) => format!("<unresolved: {reason}>"),
        }
    }

    /// Canonicalize the inner path. `Unresolved` has no path to canonicalize.
    pub fn canonicalized(&self) -> AccessScope {
        let canon = |p: &String| crate::canonicalize::best_effort_canonicalize(p);
        match self {
            Self::Exact(p) => Self::Exact(canon(p)),
            Self::Subtree(p) => Self::Subtree(canon(p)),
            Self::UnboundedSubtree(p) => Self::UnboundedSubtree(canon(p)),
            Self::Pattern(p) => Self::Pattern(canon(p)),
            Self::Unresolved(r) => Self::Unresolved(r.clone()),
        }
    }
}

/// A resolved file access: the set of paths it touches and the kind of access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccess {
    pub scope: AccessScope,
    pub kind: AccessKind,
}

impl From<String> for AccessScope {
    fn from(path: String) -> Self {
        Self::Exact(path)
    }
}

impl From<&str> for AccessScope {
    fn from(path: &str) -> Self {
        Self::Exact(path.to_string())
    }
}

impl FileAccess {
    pub fn exact(path: impl Into<String>, kind: AccessKind) -> Self {
        Self {
            scope: AccessScope::Exact(path.into()),
            kind,
        }
    }

    pub fn scoped(scope: AccessScope, kind: AccessKind) -> Self {
        Self { scope, kind }
    }
}

/// Returns true if this command's only effect is file I/O. For these commands,
/// a matching Read/Write rule is sufficient — a separate Bash() rule is not required.
///
/// `source` / `.` are excluded because they execute the sourced file.
pub fn is_file_only_command(cmd_name: &str) -> bool {
    matches!(
        cmd_name,
        "cat"
            | "head"
            | "tail"
            | "less"
            | "more"
            | "wc"
            | "file"
            | "stat"
            | "md5sum"
            | "shasum"
            | "sha256sum"
            | "xxd"
            | "hexdump"
            | "diff"
            | "grep"
            | "rg"
            | "find"
            | "ls"
            | "sort"
            | "uniq"
            | "cut"
            | "awk"
            | "sed"
            | "cp"
            | "mv"
            | "rm"
            | "rmdir"
            | "mkdir"
            | "touch"
            | "chmod"
            | "chown"
            | "chgrp"
            | "tee"
            | "ln"
            | "install"
            | "strings"
            | "readelf"
            | "objdump"
            | "nm"
            | "ldd"
            | "size"
            | "tac"
            | "nl"
            | "paste"
            | "rev"
            | "expand"
            | "unexpand"
            | "fold"
            | "column"
            | "od"
            | "zcat"
            | "bzcat"
            | "xzcat"
            | "base64"
            | "sha1sum"
            | "sha512sum"
            | "sha224sum"
            | "sha384sum"
            | "b2sum"
            | "cksum"
            | "sum"
            | "md5"
            | "otool"
            | "readlink"
            | "du"
            | "truncate"
            | "jq"
            | "gzip"
            | "gunzip"
            | "bzip2"
            | "bunzip2"
            | "xz"
            | "unxz"
            | "zip"
            | "unzip"
            | "tar"
            | "dd"
            | "patch"
            | "split"
            | "csplit"
    )
}

pub fn resolve_path(path: &str, cwd: &str) -> String {
    if crate::path_util::is_absolute(path) {
        path.to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = crate::env_hooks::hook_home() {
            let home = crate::path_util::normalize_separators(&home.to_string_lossy());
            format!("{home}/{rest}")
        } else {
            path.to_string()
        }
    } else if path == "~" {
        if let Some(home) = crate::env_hooks::hook_home() {
            crate::path_util::normalize_separators(&home.to_string_lossy())
        } else {
            path.to_string()
        }
    } else {
        format!("{cwd}/{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_scope_display_forms() {
        assert_eq!(AccessScope::Exact("/a/b".into()).display(), "/a/b");
        assert_eq!(AccessScope::Pattern("/a/*".into()).display(), "/a/*");
        assert_eq!(AccessScope::Subtree("/a/b".into()).display(), "/a/b/**");
        assert_eq!(AccessScope::Subtree("/".into()).display(), "/**");
        assert_eq!(AccessScope::Subtree("C:/".into()).display(), "C:/**");
        assert_eq!(
            AccessScope::UnboundedSubtree("/a/b".into()).display(),
            "/a/b/**+symlinks",
        );
        assert_eq!(
            AccessScope::Unresolved("$FOO".into()).display(),
            "<unresolved: $FOO>",
        );
    }

    #[test]
    fn access_scope_path_returns_inner() {
        assert_eq!(AccessScope::Subtree("/a/b".into()).path(), "/a/b");
        assert_eq!(AccessScope::Unresolved("$FOO".into()).path(), "$FOO");
    }
}
