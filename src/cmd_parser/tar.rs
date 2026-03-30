use super::{resolve, CommandFileAccesses, CommandParser};

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

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
        })
    }
}
