use super::{resolve, CommandFileAccesses, CommandParser};

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
            if matches!(
                arg,
                "-n" | "-E"
                    | "-r"
                    | "-l"
                    | "-u"
                    | "-z"
                    | "-s"
                    | "--quiet"
                    | "--silent"
                    | "--regexp-extended"
                    | "--posix"
                    | "--sandbox"
                    | "--separate"
                    | "--follow-symlinks"
                    | "--null-data"
                    | "--unbuffered"
                    | "--debug"
            ) {
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

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
        })
    }
}
