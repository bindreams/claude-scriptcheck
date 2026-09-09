use super::{resolve, resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

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
        let mut dereference = false;
        let mut runs_a_program = false;
        let mut file_args: Vec<&str> = Vec::new();
        let mut i = 0;

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
                    change_dir = Some(args[i]);
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
                    file_args.push(args[i]);
                    i += 1;
                }
                break;
            }

            // Long flags
            if let Some(rest) = arg.strip_prefix("--") {
                let (name, inline_value) = match rest.split_once('=') {
                    Some((n, _)) => (n, true),
                    None => (rest, false),
                };
                if is_program_option(name) {
                    runs_a_program = true;
                    if !inline_value {
                        // Consume the program name so it is not mistaken for a
                        // positional.
                        i += 1;
                    }
                    i += 1;
                    continue;
                }
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
                        "dereference" => dereference = true,
                        "file" => {
                            i += 1;
                            if i < args.len() {
                                archive = Some(args[i]);
                            }
                        }
                        "directory" => {
                            i += 1;
                            if i < args.len() {
                                change_dir = Some(args[i]);
                            }
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
                            if j + 1 < chars.len() {
                                let rest: String = chars[j + 1..].iter().collect();
                                change_dir = Some(Box::leak(rest.into_boxed_str()));
                            } else {
                                i += 1;
                                if i < args.len() {
                                    change_dir = Some(args[i]);
                                }
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

        // Extraction unpacks a whole tree into -C DIR, or into the working
        // directory when -C is absent.
        if mode == TarMode::Extract {
            let dest = change_dir.unwrap_or(cwd);
            writes.push(resolve_scoped(dest, cwd, Recursion::Yes));
        }

        // Positional files: in create mode → reads (files to archive). tar
        // recurses into directory operands; -h follows symlinks out of them.
        if mode == TarMode::Create || mode == TarMode::Append || mode == TarMode::Update {
            let recursion = if dereference {
                Recursion::Following
            } else {
                Recursion::IfDir
            };
            for f in &file_args {
                reads.push(resolve_scoped(f, cwd, recursion));
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
/// The short spellings `-I` and `-F` are handled alongside `-f` and `-C` in the
/// flag loops. `-I` is GNU's `--use-compress-program`; bsdtar reads it as a list
/// of member names instead. Treated as exec-capable on every platform, because
/// over-approximating costs a prompt while under-approximating leaves the hole.
fn is_program_option(name: &str) -> bool {
    matches!(
        name,
        "use-compress-program"
            | "to-command"
            | "rmt-command"
            | "rsh-command"
            | "info-script"
            | "new-volume-script"
            | "checkpoint-action"
    )
}
