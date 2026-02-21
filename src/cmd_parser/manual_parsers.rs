use super::{resolve, CommandFileAccesses, CommandParser};

// ─── find ────────────────────────────────────────────────────────────────────

/// `find` uses a predicate-based syntax that doesn't fit standard option parsing.
/// Leading arguments before the first expression token are search paths (Read).
pub(super) struct FindParser;

impl CommandParser for FindParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let mut reads = Vec::new();

        for arg in args {
            if is_find_expression_token(arg) {
                break;
            }
            reads.push(resolve(arg, cwd));
        }

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
        })
    }
}

fn is_find_expression_token(arg: &str) -> bool {
    matches!(
        arg,
        // Tests / predicates
        "-name"
        | "-iname"
        | "-type"
        | "-path"
        | "-ipath"
        | "-regex"
        | "-iregex"
        | "-size"
        | "-perm"
        | "-user"
        | "-group"
        | "-newer"
        | "-mtime"
        | "-atime"
        | "-ctime"
        | "-mmin"
        | "-amin"
        | "-cmin"
        | "-maxdepth"
        | "-mindepth"
        | "-depth"
        | "-empty"
        | "-samefile"
        | "-true"
        | "-false"
        | "-links"
        | "-inum"
        | "-xtype"
        | "-readable"
        | "-writable"
        | "-executable"
        | "-wholename"
        | "-iwholename"
        | "-lname"
        | "-ilname"
        | "-uid"
        | "-gid"
        | "-nouser"
        | "-nogroup"
        | "-xdev"
        | "-mount"
        | "-noleaf"
        | "-daystart"
        | "-warn"
        | "-nowarn"
        | "-follow"
        | "-regextype"
        | "-used"
        // Actions
        | "-exec"
        | "-execdir"
        | "-ok"
        | "-okdir"
        | "-print"
        | "-print0"
        | "-printf"
        | "-fprintf"
        | "-prune"
        | "-delete"
        | "-quit"
        | "-ls"
        | "-fls"
        | "-fprint"
        | "-fprint0"
        // Operators
        | "-not"
        | "-and"
        | "-or"
        | "-a"
        | "-o"
        | "!"
        | "("
        | ")"
        | ","
    ) || arg.starts_with("-newer") // covers -newerXY variants
}

// ─── sed ─────────────────────────────────────────────────────────────────────

/// GNU `sed -i` requires the suffix to be attached directly (no space between
/// `-i` and the suffix), so `sed -i.bak` ≠ `sed -i .bak`. clap can't model
/// this "attached-only optional value" rule, so we parse manually.
pub(super) struct SedParser;

impl CommandParser for SedParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let mut has_inplace = false;
        let mut has_explicit_script = false;
        let mut found_positional_script = false;
        let mut file_reads = Vec::new(); // -f FILE
        let mut file_paths = Vec::new(); // positional file targets

        let mut i = 0;
        while i < args.len() {
            let arg = args[i];

            if arg == "--" {
                // Everything after -- is a file path
                i += 1;
                while i < args.len() {
                    file_paths.push(args[i]);
                    i += 1;
                }
                break;
            }

            if arg == "-i" || arg == "--in-place" {
                has_inplace = true;
                i += 1;
                continue;
            }

            // -i<suffix> (attached optional value)
            if arg.starts_with("-i") && !arg.starts_with("--") && arg != "-i" {
                has_inplace = true;
                i += 1;
                continue;
            }

            // --in-place=<suffix>
            if arg.starts_with("--in-place=") {
                has_inplace = true;
                i += 1;
                continue;
            }

            // -e SCRIPT or --expression SCRIPT
            if arg == "-e" || arg == "--expression" {
                has_explicit_script = true;
                i += 2; // skip the script value
                continue;
            }
            if arg.starts_with("--expression=") {
                has_explicit_script = true;
                i += 1;
                continue;
            }

            // -f FILE or --file FILE (script file → Read)
            if arg == "-f" || arg == "--file" {
                if i + 1 < args.len() {
                    file_reads.push(args[i + 1]);
                    has_explicit_script = true;
                }
                i += 2;
                continue;
            }
            if let Some(val) = arg.strip_prefix("--file=") {
                file_reads.push(val);
                has_explicit_script = true;
                i += 1;
                continue;
            }

            // Known boolean flags
            if matches!(arg, "-n" | "-E" | "-r" | "-l" | "-u" | "-z" | "-s"
                | "--quiet" | "--silent" | "--regexp-extended" | "--posix"
                | "--sandbox" | "--separate" | "--follow-symlinks"
                | "--null-data" | "--unbuffered" | "--debug")
            {
                i += 1;
                continue;
            }

            // Combined short flags like -nE, -ni, etc.
            if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
                let chars: Vec<char> = arg[1..].chars().collect();
                let mut is_known_combo = true;
                let mut j = 0;
                while j < chars.len() {
                    match chars[j] {
                        'n' | 'E' | 'r' | 'l' | 'u' | 'z' | 's' => {
                            j += 1;
                        }
                        'i' => {
                            has_inplace = true;
                            // Rest of chars after 'i' is the suffix
                            break;
                        }
                        'e' => {
                            has_explicit_script = true;
                            // Rest of chars after 'e' is the script? No — -e takes next arg.
                            // But in combined form, if 'e' is last char, next arg is script.
                            // If not last char, the rest is the script inline.
                            if j + 1 < chars.len() {
                                // -eINLINE_SCRIPT — rest is the script
                                // We just mark has_explicit_script and move on
                            } else {
                                // -ne — next arg is script
                                i += 1; // skip next arg (the script)
                            }
                            break;
                        }
                        'f' => {
                            has_explicit_script = true;
                            if j + 1 < chars.len() {
                                // -fINLINE_FILE — rest is the filename
                                let rest: String = chars[j + 1..].iter().collect();
                                file_reads.push(Box::leak(rest.into_boxed_str()));
                            } else {
                                // -nf — next arg is the file
                                if i + 1 < args.len() {
                                    file_reads.push(args[i + 1]);
                                }
                                i += 1;
                            }
                            break;
                        }
                        _ => {
                            is_known_combo = false;
                            break;
                        }
                    }
                }
                if !is_known_combo {
                    return Err(format!("unknown sed flag: {arg}"));
                }
                i += 1;
                continue;
            }

            // Unknown long flag
            if arg.starts_with("--") {
                return Err(format!("unknown sed flag: {arg}"));
            }

            // Positional argument
            if !has_explicit_script && !found_positional_script {
                // First positional is the script (skip)
                found_positional_script = true;
            } else {
                file_paths.push(arg);
            }
            i += 1;
        }

        let mut reads: Vec<String> = file_reads.iter().map(|f| resolve(f, cwd)).collect();
        let mut writes = Vec::new();

        for path in &file_paths {
            let resolved = resolve(path, cwd);
            if has_inplace {
                writes.push(resolved);
            } else {
                reads.push(resolved);
            }
        }

        Ok(CommandFileAccesses { reads, writes })
    }
}

// ─── tar ─────────────────────────────────────────────────────────────────────

/// `tar` has two invocation styles: `tar -xf archive.tar` (POSIX) and
/// `tar xf archive.tar` (legacy, no dash). Both are handled.
pub(super) struct TarParser;

#[derive(Clone, Copy, PartialEq)]
enum TarMode {
    Create,  // c
    Extract, // x
    List,    // t
    Append,  // r
    Update,  // u
    Diff,    // d
    Unknown,
}

impl CommandParser for TarParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let mut mode = TarMode::Unknown;
        let mut archive: Option<&str> = None;
        let mut change_dir: Option<&str> = None;
        let mut file_args: Vec<&str> = Vec::new();
        let mut i = 0;

        // Check for legacy bundled syntax: first arg without '-' prefix
        if let Some(first) = args.first() {
            if !first.starts_with('-') && !first.contains('=') {
                // Legacy syntax: tar xf archive.tar ...
                let mut need_archive = false;
                let mut need_dir = false;
                let chars: Vec<char> = first.chars().collect();
                for ch in &chars {
                    match ch {
                        'c' => mode = TarMode::Create,
                        'x' => mode = TarMode::Extract,
                        't' => mode = TarMode::List,
                        'r' => mode = TarMode::Append,
                        'u' => mode = TarMode::Update,
                        'd' => mode = TarMode::Diff,
                        'f' => need_archive = true,
                        'C' => need_dir = true,
                        // Other single-char flags (v, z, j, J, p, k, etc.) — skip
                        _ => {}
                    }
                }
                i = 1;

                // Consume the value args expected by 'f' and 'C' in the bundle
                if need_archive && i < args.len() {
                    archive = Some(args[i]);
                    i += 1;
                }
                if need_dir && i < args.len() {
                    change_dir = Some(args[i]);
                    i += 1;
                }
            }
        }

        // Parse remaining args (POSIX-style)
        while i < args.len() {
            let arg = args[i];

            if arg == "--" {
                i += 1;
                while i < args.len() {
                    file_args.push(args[i]);
                    i += 1;
                }
                break;
            }

            // Long flags
            if let Some(rest) = arg.strip_prefix("--") {
                if let Some(val) = rest.strip_prefix("file=") {
                    archive = Some(val);
                } else if let Some(val) = rest.strip_prefix("directory=") {
                    change_dir = Some(val);
                } else {
                    match rest {
                        "create" => mode = TarMode::Create,
                        "extract" | "get" => mode = TarMode::Extract,
                        "list" => mode = TarMode::List,
                        "append" => mode = TarMode::Append,
                        "update" => mode = TarMode::Update,
                        "diff" | "compare" => mode = TarMode::Diff,
                        "file" => {
                            i += 1;
                            if i < args.len() { archive = Some(args[i]); }
                        }
                        "directory" => {
                            i += 1;
                            if i < args.len() { change_dir = Some(args[i]); }
                        }
                        // Other long flags — skip (no value consumption needed for
                        // flags like --verbose, --gzip, --bzip2, etc.)
                        _ => {}
                    }
                }
                i += 1;
                continue;
            }

            // Short flags
            if arg.starts_with('-') && arg.len() > 1 {
                let chars: Vec<char> = arg[1..].chars().collect();
                let mut j = 0;
                while j < chars.len() {
                    match chars[j] {
                        'c' => mode = TarMode::Create,
                        'x' => mode = TarMode::Extract,
                        't' => mode = TarMode::List,
                        'r' => mode = TarMode::Append,
                        'u' => mode = TarMode::Update,
                        'd' => mode = TarMode::Diff,
                        'f' => {
                            // Rest of bundled chars or next arg is the archive
                            if j + 1 < chars.len() {
                                let rest: String = chars[j + 1..].iter().collect();
                                archive = Some(Box::leak(rest.into_boxed_str()));
                            } else {
                                i += 1;
                                if i < args.len() { archive = Some(args[i]); }
                            }
                            break;
                        }
                        'C' => {
                            if j + 1 < chars.len() {
                                let rest: String = chars[j + 1..].iter().collect();
                                change_dir = Some(Box::leak(rest.into_boxed_str()));
                            } else {
                                i += 1;
                                if i < args.len() { change_dir = Some(args[i]); }
                            }
                            break;
                        }
                        // Other short flags (v, z, j, J, p, k, etc.) — skip
                        _ => {}
                    }
                    j += 1;
                }
                i += 1;
                continue;
            }

            // Positional arg
            file_args.push(arg);
            i += 1;
        }

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // Archive file
        if let Some(arch) = archive {
            match mode {
                TarMode::Create | TarMode::Append | TarMode::Update => {
                    writes.push(resolve(arch, cwd));
                }
                TarMode::Extract | TarMode::List | TarMode::Diff | TarMode::Unknown => {
                    reads.push(resolve(arch, cwd));
                }
            }
        }

        // -C DIR in extract mode → write destination
        if let Some(dir) = change_dir {
            if mode == TarMode::Extract {
                writes.push(resolve(dir, cwd));
            }
        }

        // Positional files: in create mode → reads (files to archive)
        if mode == TarMode::Create || mode == TarMode::Append || mode == TarMode::Update {
            for f in &file_args {
                reads.push(resolve(f, cwd));
            }
        }

        Ok(CommandFileAccesses { reads, writes })
    }
}

// ─── dd ──────────────────────────────────────────────────────────────────────

/// `dd` uses `key=value` syntax instead of standard flags.
pub(super) struct DdParser;

impl CommandParser for DdParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let mut reads = Vec::new();
        let mut writes = Vec::new();

        for arg in args {
            if let Some(val) = arg.strip_prefix("if=") {
                reads.push(resolve(val, cwd));
            } else if let Some(val) = arg.strip_prefix("of=") {
                writes.push(resolve(val, cwd));
            } else if arg.contains('=') {
                // Other key=value pairs (bs, count, skip, seek, conv, status, etc.)
                continue;
            } else {
                return Err(format!("dd: unexpected argument: {arg}"));
            }
        }

        Ok(CommandFileAccesses { reads, writes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn r(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    fn w(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    // ── find ──

    #[test]
    fn find_single_path() {
        let result = FindParser.parse(&["/tmp", "-name", "*.txt"], "/cwd").unwrap();
        assert_eq!(result.reads, r(&["/tmp"]));
        assert!(result.writes.is_empty());
    }

    #[test]
    fn find_multiple_paths() {
        let result = FindParser.parse(&["/tmp", "/var", "-type", "f"], "/cwd").unwrap();
        assert_eq!(result.reads, r(&["/tmp", "/var"]));
    }

    #[test]
    fn find_relative_path() {
        let result = FindParser.parse(&[".", "-name", "*.rs"], "/home/user").unwrap();
        assert_eq!(result.reads, r(&["/home/user/."]));
    }

    #[test]
    fn find_no_path_expression_first() {
        let result = FindParser.parse(&["-name", "*.txt"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
    }

    #[test]
    fn find_with_negation() {
        let result = FindParser.parse(&["/tmp", "!", "-name", "*.log"], "/cwd").unwrap();
        assert_eq!(result.reads, r(&["/tmp"]));
    }

    #[test]
    fn find_with_parens() {
        let result = FindParser.parse(&["/tmp", "(", "-name", "*.txt", ")"], "/cwd").unwrap();
        assert_eq!(result.reads, r(&["/tmp"]));
    }

    #[test]
    fn find_exec() {
        let result = FindParser.parse(
            &["/tmp", "-name", "*.txt", "-exec", "rm", "{}", ";"],
            "/cwd",
        ).unwrap();
        assert_eq!(result.reads, r(&["/tmp"]));
    }

    #[test]
    fn find_maxdepth_before_path() {
        // find -maxdepth 1 . — maxdepth is an expression, so no paths extracted
        let result = FindParser.parse(&["-maxdepth", "1", "."], "/tmp").unwrap();
        assert!(result.reads.is_empty());
    }

    #[test]
    fn find_newer_variant() {
        let result = FindParser.parse(&["/tmp", "-newermt", "2023-01-01"], "/cwd").unwrap();
        assert_eq!(result.reads, r(&["/tmp"]));
    }

    // ── sed ──

    #[test]
    fn sed_basic_read() {
        let result = SedParser.parse(&["s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/file.txt"]));
        assert!(result.writes.is_empty());
    }

    #[test]
    fn sed_inplace_is_write() {
        let result = SedParser.parse(&["-i", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.writes, w(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_inplace_with_suffix() {
        let result = SedParser.parse(&["-i.bak", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.writes, w(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_inplace_long_form() {
        let result = SedParser.parse(&["--in-place", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.writes, w(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_inplace_long_form_with_suffix() {
        let result = SedParser.parse(&["--in-place=.bak", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.writes, w(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_e_flag_consumes_script() {
        let result = SedParser.parse(&["-e", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_multiple_e_flags() {
        let result = SedParser.parse(
            &["-e", "s/foo/bar/", "-e", "s/baz/qux/", "file.txt"],
            "/tmp",
        ).unwrap();
        assert_eq!(result.reads, r(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_f_flag_is_read() {
        let result = SedParser.parse(&["-f", "script.sed", "file.txt"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/script.sed", "/tmp/file.txt"]));
    }

    #[test]
    fn sed_n_flag_is_boolean() {
        let result = SedParser.parse(&["-n", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_combined_flags_ni() {
        let result = SedParser.parse(&["-ni", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.writes, w(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_combined_flags_ne() {
        let result = SedParser.parse(&["-ne", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/file.txt"]));
    }

    #[test]
    fn sed_script_only_no_files() {
        let result = SedParser.parse(&["s/foo/bar/"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert!(result.writes.is_empty());
    }

    #[test]
    fn sed_inplace_multiple_files() {
        let result = SedParser.parse(&["-i", "s/foo/bar/", "a.txt", "b.txt"], "/tmp").unwrap();
        assert_eq!(result.writes, w(&["/tmp/a.txt", "/tmp/b.txt"]));
    }

    #[test]
    fn sed_unknown_flag_fails() {
        let result = SedParser.parse(&["--bogus", "s/foo/bar/", "file.txt"], "/tmp");
        assert!(result.is_err());
    }

    #[test]
    fn sed_double_dash_files() {
        let result = SedParser.parse(&["-e", "s/a/b/", "--", "-weird-file"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/-weird-file"]));
    }

    // ── tar ──

    #[test]
    fn tar_create_mode() {
        let result = TarParser.parse(&["-cf", "archive.tar", "dir/"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/dir/"]));
        assert_eq!(result.writes, w(&["/tmp/archive.tar"]));
    }

    #[test]
    fn tar_extract_mode() {
        let result = TarParser.parse(&["-xf", "archive.tar"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
        assert!(result.writes.is_empty());
    }

    #[test]
    fn tar_extract_to_dir() {
        let result = TarParser.parse(&["-xf", "a.tar", "-C", "/dest"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/a.tar"]));
        assert_eq!(result.writes, w(&["/dest"]));
    }

    #[test]
    fn tar_legacy_syntax() {
        let result = TarParser.parse(&["xf", "archive.tar"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    }

    #[test]
    fn tar_legacy_create() {
        let result = TarParser.parse(&["czf", "archive.tar.gz", "src/"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/src/"]));
        assert_eq!(result.writes, w(&["/tmp/archive.tar.gz"]));
    }

    #[test]
    fn tar_list_mode() {
        let result = TarParser.parse(&["-tf", "archive.tar"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    }

    #[test]
    fn tar_long_flags() {
        let result = TarParser.parse(
            &["--create", "--file", "archive.tar", "--directory", "/src", "."],
            "/tmp",
        ).unwrap();
        assert_eq!(result.reads, r(&["/tmp/."]));
        assert_eq!(result.writes, w(&["/tmp/archive.tar"]));
    }

    #[test]
    fn tar_long_flag_equals() {
        let result = TarParser.parse(&["--extract", "--file=archive.tar"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    }

    // ── dd ──

    #[test]
    fn dd_basic() {
        let result = DdParser.parse(&["if=input.bin", "of=output.bin", "bs=4096"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/tmp/input.bin"]));
        assert_eq!(result.writes, w(&["/tmp/output.bin"]));
    }

    #[test]
    fn dd_only_input() {
        let result = DdParser.parse(&["if=/dev/urandom", "bs=1M", "count=1"], "/tmp").unwrap();
        assert_eq!(result.reads, r(&["/dev/urandom"]));
        assert!(result.writes.is_empty());
    }

    #[test]
    fn dd_only_output() {
        let result = DdParser.parse(&["of=/tmp/zeros", "bs=1M", "count=100"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.writes, w(&["/tmp/zeros"]));
    }

    #[test]
    fn dd_unknown_arg_fails() {
        let result = DdParser.parse(&["if=input", "badarg"], "/tmp");
        assert!(result.is_err());
    }
}
