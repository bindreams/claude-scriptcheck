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
            inline_script_start: None,
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

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
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

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
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

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

// ─── Script runners ─────────────────────────────────────────────────────────
//
// These parsers detect inline-script invocations (-c/-e) and report
// `inline_script_start` so the checker can log `Bash(cmd -c *)` instead of
// including the literal script text in the missing rule.

/// Shared parser for POSIX-family shells: bash, sh, zsh, dash.
///
/// Modes:
///   - `shell -c SCRIPT [$0 [args…]]` — inline script, no file access.
///   - `shell [flags] FILE [args…]`    — script file → Read.
///   - `shell` / `shell -s`            — interactive / stdin.
pub(super) struct ShellParser;

impl CommandParser for ShellParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_shell_runner(args, cwd)
    }
}

fn parse_shell_runner(
    args: &[&str],
    cwd: &str,
) -> Result<CommandFileAccesses, String> {
    let mut has_s = false;
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == "--" {
            break; // remaining are positional
        }

        // Short flag or cluster
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            let chars: Vec<char> = arg[1..].chars().collect();
            for (j, &ch) in chars.iter().enumerate() {
                match ch {
                    'c' => {
                        // Script text is the NEXT argument
                        i += 1;
                        let inline_script_start =
                            if i < args.len() { Some(i) } else { None };
                        return Ok(CommandFileAccesses {
                            reads: Vec::new(),
                            writes: Vec::new(),
                            inline_script_start,
                        });
                    }
                    's' => {
                        has_s = true;
                    }
                    'o' => {
                        // -o takes a value; if last in cluster, consume next arg
                        if j + 1 == chars.len() {
                            i += 1;
                        }
                        break;
                    }
                    // All other single-char flags are boolean
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        // Long options (--posix, --norc, --noprofile, --login, …) — boolean
        if arg.starts_with("--") {
            i += 1;
            continue;
        }

        // First positional: script file (if we reach here, -c was not seen)
        if !has_s {
            return Ok(CommandFileAccesses {
                reads: vec![resolve(arg, cwd)],
                writes: Vec::new(),
                inline_script_start: None,
            });
        }

        break;
    }

    // Interactive / stdin mode
    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes: Vec::new(),
        inline_script_start: None,
    })
}

// ─── python ─────────────────────────────────────────────────────────────────

/// Parser for `python` / `python3`.
///
/// Modes:
///   - `python -c SCRIPT [args…]` — inline script.
///   - `python -m MODULE [args…]` — module execution, no file access.
///   - `python FILE [args…]`      — script file → Read.
///   - `python -` / `python`      — stdin / interactive.
pub(super) struct PythonParser;

impl CommandParser for PythonParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_python_runner(args, cwd)
    }
}

fn parse_python_runner(
    args: &[&str],
    cwd: &str,
) -> Result<CommandFileAccesses, String> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == "--" {
            break;
        }

        if arg == "-" {
            // Read from stdin
            return Ok(CommandFileAccesses {
                reads: Vec::new(),
                writes: Vec::new(),
                inline_script_start: None,
            });
        }

        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            let chars: Vec<char> = arg[1..].chars().collect();
            for (j, &ch) in chars.iter().enumerate() {
                match ch {
                    'c' => {
                        i += 1;
                        let inline_script_start =
                            if i < args.len() { Some(i) } else { None };
                        return Ok(CommandFileAccesses {
                            reads: Vec::new(),
                            writes: Vec::new(),
                            inline_script_start,
                        });
                    }
                    'm' => {
                        // -m MODULE — no file access from module name
                        return Ok(CommandFileAccesses {
                            reads: Vec::new(),
                            writes: Vec::new(),
                            inline_script_start: None,
                        });
                    }
                    'W' | 'X' => {
                        // Value-consuming flags
                        if j + 1 == chars.len() {
                            i += 1;
                        }
                        break;
                    }
                    // Boolean: B, d, E, i, I, O, s, S, u, v, x, q, b, …
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        // Long options (--version, --help, …) — skip
        if arg.starts_with("--") {
            i += 1;
            continue;
        }

        // First positional: script file
        return Ok(CommandFileAccesses {
            reads: vec![resolve(arg, cwd)],
            writes: Vec::new(),
            inline_script_start: None,
        });
    }

    // Interactive / stdin
    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes: Vec::new(),
        inline_script_start: None,
    })
}

// ─── ruby ───────────────────────────────────────────────────────────────────

/// Parser for `ruby`.
///
/// Modes:
///   - `ruby -e CODE [args…]` — inline script (repeatable).
///   - `ruby FILE [args…]`    — script file → Read.
pub(super) struct RubyParser;

impl CommandParser for RubyParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_ruby_runner(args, cwd)
    }
}

fn parse_ruby_runner(
    args: &[&str],
    cwd: &str,
) -> Result<CommandFileAccesses, String> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == "--" {
            break;
        }

        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            let chars: Vec<char> = arg[1..].chars().collect();
            for (j, &ch) in chars.iter().enumerate() {
                match ch {
                    'e' => {
                        i += 1;
                        let inline_script_start =
                            if i < args.len() { Some(i) } else { None };
                        return Ok(CommandFileAccesses {
                            reads: Vec::new(),
                            writes: Vec::new(),
                            inline_script_start,
                        });
                    }
                    'r' | 'I' | 'C' | 'F' | 'E' | 'K' => {
                        // Value-consuming flags
                        if j + 1 == chars.len() {
                            i += 1;
                        }
                        break;
                    }
                    // Boolean: a, c, d, l, n, p, s, v, w, x, y, …
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with("--") {
            i += 1;
            continue;
        }

        // First positional: script file
        return Ok(CommandFileAccesses {
            reads: vec![resolve(arg, cwd)],
            writes: Vec::new(),
            inline_script_start: None,
        });
    }

    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes: Vec::new(),
        inline_script_start: None,
    })
}

// ─── node ───────────────────────────────────────────────────────────────────

/// Parser for `node` / `nodejs`.
///
/// Modes:
///   - `node -e CODE` / `node --eval CODE` — inline script.
///   - `node -p CODE` / `node --print CODE` — inline script (eval + print).
///   - `node FILE [args…]` — script file → Read.
///
/// Note: `-c` in node is `--check` (syntax check), NOT inline script.
pub(super) struct NodeParser;

impl CommandParser for NodeParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_node_runner(args, cwd)
    }
}

fn parse_node_runner(
    args: &[&str],
    cwd: &str,
) -> Result<CommandFileAccesses, String> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == "--" {
            break;
        }

        // Long --eval / --print with separate value
        if arg == "--eval" || arg == "--print" {
            i += 1;
            let inline_script_start = if i < args.len() { Some(i) } else { None };
            return Ok(CommandFileAccesses {
                reads: Vec::new(),
                writes: Vec::new(),
                inline_script_start,
            });
        }
        // Long --eval=CODE / --print=CODE
        if arg.starts_with("--eval=") || arg.starts_with("--print=") {
            return Ok(CommandFileAccesses {
                reads: Vec::new(),
                writes: Vec::new(),
                inline_script_start: Some(i),
            });
        }

        // Short flags
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            let chars: Vec<char> = arg[1..].chars().collect();
            for (j, &ch) in chars.iter().enumerate() {
                match ch {
                    'e' | 'p' => {
                        i += 1;
                        let inline_script_start =
                            if i < args.len() { Some(i) } else { None };
                        return Ok(CommandFileAccesses {
                            reads: Vec::new(),
                            writes: Vec::new(),
                            inline_script_start,
                        });
                    }
                    'r' => {
                        // -r MODULE — value-consuming
                        if j + 1 == chars.len() {
                            i += 1;
                        }
                        break;
                    }
                    // -c = --check (boolean), and other boolean flags
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        // Other long flags
        if arg.starts_with("--") {
            if arg.contains('=') {
                // --foo=bar form — already consumed
                i += 1;
                continue;
            }
            // Check known boolean flags
            match arg {
                "--check" | "--interactive" | "--no-deprecation"
                | "--no-warnings" | "--preserve-symlinks"
                | "--throw-deprecation" | "--trace-deprecation"
                | "--trace-warnings" | "--zero-fill-buffers" => {
                    i += 1;
                    continue;
                }
                _ => {
                    // Assume value-taking
                    i += 2;
                    continue;
                }
            }
        }

        // First positional: script file
        return Ok(CommandFileAccesses {
            reads: vec![resolve(arg, cwd)],
            writes: Vec::new(),
            inline_script_start: None,
        });
    }

    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes: Vec::new(),
        inline_script_start: None,
    })
}

// ─── perl ───────────────────────────────────────────────────────────────────

/// Parser for `perl`.
///
/// Modes:
///   - `perl -e CODE` / `perl -E CODE` — inline script (repeatable).
///   - `perl FILE [args…]` — script file → Read.
pub(super) struct PerlParser;

impl CommandParser for PerlParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_perl_runner(args, cwd)
    }
}

fn parse_perl_runner(
    args: &[&str],
    cwd: &str,
) -> Result<CommandFileAccesses, String> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == "--" {
            break;
        }

        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            let chars: Vec<char> = arg[1..].chars().collect();
            for (j, &ch) in chars.iter().enumerate() {
                match ch {
                    'e' | 'E' => {
                        // If chars remain after the flag, the rest is embedded script
                        // text (e.g. -e'print 1').  Either way, inline script is present.
                        if j + 1 < chars.len() {
                            // Embedded: the whole arg contains the script
                            return Ok(CommandFileAccesses {
                                reads: Vec::new(),
                                writes: Vec::new(),
                                inline_script_start: Some(i),
                            });
                        }
                        i += 1;
                        let inline_script_start =
                            if i < args.len() { Some(i) } else { None };
                        return Ok(CommandFileAccesses {
                            reads: Vec::new(),
                            writes: Vec::new(),
                            inline_script_start,
                        });
                    }
                    'I' | 'F' | 'm' | 'M' => {
                        if j + 1 == chars.len() {
                            i += 1;
                        }
                        break;
                    }
                    // Boolean: a, c, d, l, n, p, s, t, T, u, U, v, w, W, X, …
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with("--") {
            i += 1;
            continue;
        }

        // First positional: script file
        return Ok(CommandFileAccesses {
            reads: vec![resolve(arg, cwd)],
            writes: Vec::new(),
            inline_script_start: None,
        });
    }

    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes: Vec::new(),
        inline_script_start: None,
    })
}
