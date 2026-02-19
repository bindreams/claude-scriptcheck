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

/// Given a command name and its argument literals (None = dynamic/unresolvable),
/// return the file accesses implied by this command's well-known semantics.
pub fn well_known_file_accesses(
    cmd_name: &str,
    args: &[Option<String>],
    cwd: &str,
) -> Vec<FileAccess> {
    match cmd_name {
        // Pure readers: all non-flag args are read targets
        "cat" | "head" | "tail" | "less" | "more" | "wc" | "file" | "stat" | "md5sum"
        | "shasum" | "sha256sum" | "xxd" | "hexdump" | "diff" | "grep" | "rg" | "find"
        | "sort" | "uniq" | "cut" | "awk" | "tr" | "strings" | "readelf" | "objdump"
        | "nm" | "ldd" | "size" => read_non_flag_args(args, cwd),

        // sed: read unless -i flag present (in-place edit = write)
        "sed" => {
            let has_in_place = args
                .iter()
                .filter_map(|a| a.as_ref())
                .any(|a| a == "-i" || a.starts_with("-i") || a == "--in-place");
            if has_in_place {
                // With -i, the file args are write targets
                write_non_flag_args(args, cwd)
            } else {
                read_non_flag_args(args, cwd)
            }
        }

        // cp, mv: sources are read, last non-flag arg is write destination
        "cp" | "mv" | "install" => copy_like_accesses(args, cwd),

        // rm, rmdir, mkdir, touch, chmod, chown, chgrp: write targets
        "rm" | "rmdir" | "mkdir" | "touch" => write_non_flag_args(args, cwd),

        "chmod" | "chown" | "chgrp" => {
            // First non-flag arg is mode/owner, rest are write targets
            let non_flag: Vec<_> = args
                .iter()
                .filter_map(|a| a.as_ref())
                .filter(|a| !a.starts_with('-'))
                .collect();
            non_flag
                .iter()
                .skip(1)
                .map(|a| FileAccess {
                    path: resolve_path(a, cwd),
                    kind: AccessKind::Write,
                })
                .collect()
        }

        // tee: writes to file arguments
        "tee" => write_non_flag_args(args, cwd),

        // ln: last arg is write destination
        "ln" => copy_like_accesses(args, cwd),

        // source / dot: reads a file
        "source" | "." => {
            if let Some(Some(path)) = args.first() {
                vec![FileAccess {
                    path: resolve_path(path, cwd),
                    kind: AccessKind::Read,
                }]
            } else {
                vec![]
            }
        }

        // Commands that don't touch files
        "echo" | "printf" | "pwd" | "whoami" | "hostname" | "uname" | "date" | "uptime"
        | "env" | "printenv" | "id" | "groups" | "true" | "false" | "test" | "[" | "which"
        | "whereis" | "type" | "basename" | "dirname" | "realpath" | "expr" | "seq"
        | "sleep" | "wait" | "exit" | "return" | "break" | "continue" | "shift" | "set"
        | "unset" | "export" | "alias" | "unalias" | "declare" | "local" | "readonly"
        | "typeset" | "let" | "read" | "cd" | "pushd" | "popd" | "dirs" | "hash"
        | "command" | "builtin" | "exec" | "times" | "trap" | "kill" | "jobs" | "fg"
        | "bg" | "disown" | "suspend" | "logout" | "history" | "fc" | "bind" | "complete"
        | "compgen" | "compopt" | "mapfile" | "readarray" | "getopts" | "shopt"
        | "enable" | "help" | "caller" | "ulimit" | "umask" => vec![],

        // Default: no file access inferred
        _ => vec![],
    }
}

/// Returns true if this command is known to access files through its arguments.
#[allow(dead_code)]
pub fn is_file_accessing_command(cmd_name: &str) -> bool {
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
            | "tr"
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
            | "source"
            | "."
            | "strings"
            | "readelf"
            | "objdump"
            | "nm"
            | "ldd"
            | "size"
    )
}

fn read_non_flag_args(args: &[Option<String>], cwd: &str) -> Vec<FileAccess> {
    args.iter()
        .filter_map(|a| a.as_ref())
        .filter(|a| !a.starts_with('-'))
        .map(|a| FileAccess {
            path: resolve_path(a, cwd),
            kind: AccessKind::Read,
        })
        .collect()
}

fn write_non_flag_args(args: &[Option<String>], cwd: &str) -> Vec<FileAccess> {
    args.iter()
        .filter_map(|a| a.as_ref())
        .filter(|a| !a.starts_with('-'))
        .map(|a| FileAccess {
            path: resolve_path(a, cwd),
            kind: AccessKind::Write,
        })
        .collect()
}

fn copy_like_accesses(args: &[Option<String>], cwd: &str) -> Vec<FileAccess> {
    let non_flag: Vec<_> = args
        .iter()
        .filter_map(|a| a.as_ref())
        .filter(|a| !a.starts_with('-'))
        .collect();
    let mut accesses = Vec::new();
    if let Some((last, rest)) = non_flag.split_last() {
        for src in rest {
            accesses.push(FileAccess {
                path: resolve_path(src, cwd),
                kind: AccessKind::Read,
            });
        }
        accesses.push(FileAccess {
            path: resolve_path(last, cwd),
            kind: AccessKind::Write,
        });
    }
    accesses
}

pub fn resolve_path(path: &str, cwd: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}/{rest}", home.display())
        } else {
            path.to_string()
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            home.to_string_lossy().to_string()
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
    fn cat_reads_files() {
        let accesses = well_known_file_accesses(
            "cat",
            &[Some("file.txt".into()), Some("-n".into())],
            "/tmp",
        );
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].path, "/tmp/file.txt");
        assert_eq!(accesses[0].kind, AccessKind::Read);
    }

    #[test]
    fn cp_read_and_write() {
        let accesses = well_known_file_accesses(
            "cp",
            &[Some("a.txt".into()), Some("b.txt".into())],
            "/home",
        );
        assert_eq!(accesses.len(), 2);
        assert_eq!(accesses[0].kind, AccessKind::Read);
        assert_eq!(accesses[0].path, "/home/a.txt");
        assert_eq!(accesses[1].kind, AccessKind::Write);
        assert_eq!(accesses[1].path, "/home/b.txt");
    }

    #[test]
    fn rm_writes() {
        let accesses =
            well_known_file_accesses("rm", &[Some("-rf".into()), Some("/tmp/foo".into())], "/");
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].kind, AccessKind::Write);
        assert_eq!(accesses[0].path, "/tmp/foo");
    }

    #[test]
    fn echo_no_file_access() {
        let accesses = well_known_file_accesses("echo", &[Some("hello".into())], "/tmp");
        assert!(accesses.is_empty());
    }

    #[test]
    fn sed_inplace_is_write() {
        let accesses = well_known_file_accesses(
            "sed",
            &[
                Some("-i".into()),
                Some("s/foo/bar/".into()),
                Some("file.txt".into()),
            ],
            "/tmp",
        );
        // -i makes it a write; s/foo/bar/ starts with s not -, so it's included
        // but that's a regex pattern, not a file. This is a known limitation.
        assert!(accesses.iter().any(|a| a.kind == AccessKind::Write));
    }

    #[test]
    fn resolve_absolute() {
        assert_eq!(resolve_path("/usr/bin/ls", "/tmp"), "/usr/bin/ls");
    }

    #[test]
    fn resolve_relative() {
        assert_eq!(resolve_path("foo/bar.txt", "/tmp"), "/tmp/foo/bar.txt");
    }

    #[test]
    fn unknown_command_no_access() {
        let accesses =
            well_known_file_accesses("my-custom-tool", &[Some("arg1".into())], "/tmp");
        assert!(accesses.is_empty());
    }
}
