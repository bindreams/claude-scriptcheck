use super::{resolve, CommandFileAccesses, CommandParser};

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

fn parse_shell_runner(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
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
                        let inline_script_start = if i < args.len() { Some(i) } else { None };
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

fn parse_python_runner(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
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
                        let inline_script_start = if i < args.len() { Some(i) } else { None };
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

fn parse_ruby_runner(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
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
                        let inline_script_start = if i < args.len() { Some(i) } else { None };
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

fn parse_node_runner(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
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
                        let inline_script_start = if i < args.len() { Some(i) } else { None };
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
                "--check"
                | "--interactive"
                | "--no-deprecation"
                | "--no-warnings"
                | "--preserve-symlinks"
                | "--throw-deprecation"
                | "--trace-deprecation"
                | "--trace-warnings"
                | "--zero-fill-buffers" => {
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

fn parse_perl_runner(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
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
                        let inline_script_start = if i < args.len() { Some(i) } else { None };
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
