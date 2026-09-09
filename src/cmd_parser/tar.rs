use super::helpers::strip_program_options;
use super::{resolve, resolve_scoped, resolve_str, CommandFileAccesses, CommandParser, Recursion};

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
        let mut dereference = false;
        // `-C` applies to the operands that *follow* it, and a relative `-C`
        // resolves against the one before it (both verified against GNU tar
        // 1.35), so the directory is carried along and each operand is paired
        // with the one in effect where it appeared.
        let mut current_dir = cwd.to_string();
        let mut change_dirs: Vec<String> = Vec::new();
        let mut file_args: Vec<(&str, String)> = Vec::new();
        let mut i = 0;

        // Long options naming a program come off first, by prefix, so no
        // abbreviation can slip past the guardrail into the "skip unknown long
        // flags" arm below.
        let (args, mut runs_a_program) =
            strip_program_options(args, PROGRAM_OPTIONS, NON_EXEC_PREFIXES);
        let args: &[&str] = &args;

        // Check for legacy bundled syntax: first arg without '-' prefix
        if let Some(first) = args.first() {
            if !first.starts_with('-') && !first.contains('=') {
                // Legacy syntax: tar xf archive.tar ...
                let mut need_archive = false;
                let mut need_dir = false;
                let mut need_program = false;
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
                        'h' => dereference = true,
                        'I' | 'F' => {
                            runs_a_program = true;
                            need_program = true;
                        }
                        // Other single-char flags (v, z, j, J, p, k, etc.) — skip
                        _ => {}
                    }
                }
                i = 1;

                // Consume the value args expected by 'f', 'C' and the program
                // letters. The order here is fixed rather than the order the
                // letters appear, which is a pre-existing approximation: an
                // invocation naming a program requires a Bash rule regardless
                // of which path lands in which slot.
                if need_archive && i < args.len() {
                    archive = Some(args[i]);
                    i += 1;
                }
                if need_dir && i < args.len() {
                    current_dir = resolve_str(args[i], &current_dir);
                    change_dirs.push(current_dir.clone());
                    i += 1;
                }
                if need_program && i < args.len() {
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
                    file_args.push((args[i], current_dir.clone()));
                    i += 1;
                }
                break;
            }

            // Long flags
            if let Some(rest) = arg.strip_prefix("--") {
                let (name, inline_value) = match rest.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (rest, None),
                };
                // A value-taking option takes the next token when it was not
                // written with `=`.
                let take_value = |i: &mut usize| match inline_value {
                    Some(value) => Some(value),
                    None => {
                        *i += 1;
                        args.get(*i).copied()
                    }
                };
                match resolve_long(name) {
                    Some("create") => mode = TarMode::Create,
                    Some("extract") | Some("get") => mode = TarMode::Extract,
                    Some("list") => mode = TarMode::List,
                    Some("append") => mode = TarMode::Append,
                    Some("update") => mode = TarMode::Update,
                    Some("diff") | Some("compare") => mode = TarMode::Diff,
                    Some("dereference") => dereference = true,
                    Some("file") => archive = take_value(&mut i),
                    Some("directory") => {
                        if let Some(dir) = take_value(&mut i) {
                            current_dir = resolve_str(dir, &current_dir);
                            change_dirs.push(current_dir.clone());
                        }
                    }
                    // Unresolvable: an unknown option, or an abbreviation the
                    // real tar would call ambiguous and exit over.
                    _ => {}
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
                        'h' => dereference = true,
                        'f' => {
                            // Rest of bundled chars or next arg is the archive
                            if j + 1 < chars.len() {
                                let rest: String = chars[j + 1..].iter().collect();
                                archive = Some(Box::leak(rest.into_boxed_str()));
                            } else {
                                i += 1;
                                if i < args.len() {
                                    archive = Some(args[i]);
                                }
                            }
                            break;
                        }
                        'C' => {
                            let dir = if j + 1 < chars.len() {
                                Some(chars[j + 1..].iter().collect::<String>())
                            } else {
                                i += 1;
                                args.get(i).map(|d| (*d).to_string())
                            };
                            if let Some(dir) = dir {
                                current_dir = resolve_str(&dir, &current_dir);
                                change_dirs.push(current_dir.clone());
                            }
                            break;
                        }
                        'I' | 'F' => {
                            runs_a_program = true;
                            // Consume the program name, bundled (`-Icmd`) or
                            // separate (`-I cmd`), so it is not read as a path.
                            if j + 1 >= chars.len() {
                                i += 1;
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

            // Positional arg, tagged with the directory in effect here.
            file_args.push((arg, current_dir.clone()));
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

        // Extraction unpacks a whole tree into -C DIR, or into the working
        // directory when -C is absent. Members following each `-C` land in that
        // directory, so every one of them is a destination.
        if mode == TarMode::Extract {
            if change_dirs.is_empty() {
                writes.push(resolve_scoped(cwd, cwd, Recursion::Yes));
            } else {
                for dest in &change_dirs {
                    writes.push(resolve_scoped(dest, cwd, Recursion::Yes));
                }
            }
        }

        // Positional files: in create mode → reads (files to archive). tar
        // recurses into directory operands; -h follows symlinks out of them.
        if mode == TarMode::Create || mode == TarMode::Append || mode == TarMode::Update {
            let recursion = if dereference {
                Recursion::Following
            } else {
                Recursion::IfDir
            };
            for (f, dir) in &file_args {
                reads.push(resolve_scoped(f, dir, recursion));
            }
        }

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: if runs_a_program { Some(false) } else { None },
            ..Default::default()
        })
    }
}

/// Long options whose value is a command `tar` executes: the compression filter,
/// the per-member `--to-command` pipe, the remote-shell hooks, the volume-change
/// scripts and `--checkpoint-action=exec=…`. No `Read`/`Write` rule can gate
/// them, so the invocation needs the `Bash(...)` rule that gates execution.
///
/// Matched by prefix — see `strip_program_options`. GNU tar 1.35 executes the
/// program for `--use-compress-program`, `--use-compress-prog`, `--use-compress`,
/// `--use-comp` and `--use` alike.
///
/// The fixed-program filters (`-z`, `-j`, `-J`, `--zstd`, `--lzip`, …) are
/// excluded on the same reasoning as `rg -z`: they run a decompressor from a
/// fixed internal list resolved through `PATH`, not one the caller names.
const PROGRAM_OPTIONS: &[&str] = &[
    "use-compress-program",
    "to-command",
    "rmt-command",
    "rsh-command",
    "info-script",
    "new-volume-script",
    "checkpoint-action",
];

/// `--checkpoint` displays progress and is harmless, but it is also a strict
/// prefix of `--checkpoint-action`, which executes one. The exact spelling
/// resolves to itself in `getopt_long`, and must here too.
const NON_EXEC_PREFIXES: &[&str] = &["checkpoint"];

/// The long options this parser acts on. `-I`/`-F`, the short spellings of two
/// `PROGRAM_OPTIONS` entries, are handled in the flag loops instead: `-I` is
/// GNU's `--use-compress-program` while bsdtar reads it as a list of member
/// names, so it is treated as exec-capable on every platform — over-approximating
/// costs a prompt, under-approximating leaves the hole.
const LONG_OPTIONS: &[&str] = &[
    "append",
    "compare",
    "create",
    "dereference",
    "diff",
    "directory",
    "extract",
    "file",
    "get",
    "list",
    "update",
];

/// Resolve a long-option name the way `getopt_long` does: exact match first,
/// then a unique prefix. An ambiguous abbreviation resolves to nothing, which
/// matches the real tar — it exits with an error, so the command never runs.
///
/// This table is a subset of tar's options, so an abbreviation can be unique
/// here while being ambiguous for tar itself. That direction is harmless: tar
/// does nothing while scriptcheck has merely recorded an extra access. The
/// dangerous direction — an abbreviation of an exec-bearing option resolving to
/// something harmless — cannot happen, because `strip_program_options` has
/// already matched those against the full exec set by prefix.
fn resolve_long(name: &str) -> Option<&'static str> {
    if let Some(exact) = LONG_OPTIONS.iter().find(|option| **option == name) {
        return Some(exact);
    }
    let mut matches = LONG_OPTIONS
        .iter()
        .filter(|option| option.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}
