/// Kinds of file access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

/// A resolved file access: a path and the kind of access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccess {
    pub path: String,
    pub kind: AccessKind,
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
        if let Some(home) = dirs::home_dir() {
            let home = crate::path_util::normalize_separators(&home.to_string_lossy());
            format!("{home}/{rest}")
        } else {
            path.to_string()
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            crate::path_util::normalize_separators(&home.to_string_lossy())
        } else {
            path.to_string()
        }
    } else {
        format!("{cwd}/{path}")
    }
}
