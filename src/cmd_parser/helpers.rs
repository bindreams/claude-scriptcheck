use clap::{Arg, ArgAction, ArgMatches, Command};

use super::{resolve, CommandFileAccesses};

pub(super) fn base_cmd(name: &str) -> Command {
    Command::new(name.to_string())
        .no_binary_name(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
}

/// Boolean flag with short form only.
pub(super) fn bool_s(short: char) -> Arg {
    Arg::new(format!("bool_{short}"))
        .short(short)
        .action(ArgAction::Count)
        .required(false)
}

/// Boolean flag with both short and long forms.
pub(super) fn flag(short: char, long: &str) -> Arg {
    Arg::new(long.to_string())
        .short(short)
        .long(long.to_string())
        .action(ArgAction::Count)
        .required(false)
}

/// Long-only boolean flag.
pub(super) fn flag_l(long: &str) -> Arg {
    Arg::new(long.to_string())
        .long(long.to_string())
        .action(ArgAction::Count)
        .required(false)
}

/// Value-taking flag with short form only.
pub(super) fn val_s(short: char) -> Arg {
    Arg::new(format!("val_{short}"))
        .short(short)
        .num_args(1)
        .action(ArgAction::Append)
        .required(false)
}

/// Value-taking flag with both short and long forms.
pub(super) fn val(short: char, long: &str) -> Arg {
    Arg::new(long.to_string())
        .short(short)
        .long(long.to_string())
        .num_args(1)
        .action(ArgAction::Append)
        .required(false)
}

/// Long-only value-taking flag.
pub(super) fn val_l(long: &str) -> Arg {
    Arg::new(long.to_string())
        .long(long.to_string())
        .num_args(1)
        .action(ArgAction::Append)
        .required(false)
}

/// Positional arg for file paths. Clap handles `--` natively, so
/// `rm -- -weird-file` works without `allow_hyphen_values`.
pub(super) fn files_arg() -> Arg {
    Arg::new("files").num_args(..)
}

/// Extract resolved read paths from the "files" positional.
pub(super) fn extract_positional_reads(matches: &ArgMatches, cwd: &str) -> CommandFileAccesses {
    let reads = matches
        .get_many::<String>("files")
        .map(|vals| vals.map(|f| resolve(f, cwd)).collect())
        .unwrap_or_default();
    CommandFileAccesses {
        reads,
        writes: Vec::new(),
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    }
}

/// Extract resolved write paths from the "files" positional.
pub(super) fn extract_positional_writes(matches: &ArgMatches, cwd: &str) -> CommandFileAccesses {
    let writes = matches
        .get_many::<String>("files")
        .map(|vals| vals.map(|f| resolve(f, cwd)).collect())
        .unwrap_or_default();
    CommandFileAccesses {
        reads: Vec::new(),
        writes,
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    }
}

pub(super) fn parse_with(
    cmd: Command,
    args: &[&str],
    cwd: &str,
    extract: fn(&ArgMatches, &str) -> CommandFileAccesses,
) -> Result<CommandFileAccesses, String> {
    let matches = cmd.try_get_matches_from(args).map_err(|e| e.to_string())?;
    Ok(extract(&matches, cwd))
}

/// Strip legacy `-NUM[suffix]` / `+NUM[suffix]` shorthand args used by
/// head and tail.  These are not file paths and don't consume the next arg,
/// so we can safely remove them before clap parses the rest.
///
/// `allow_plus` enables `+NUM[suffix]` recognition (needed for `tail`).
pub(super) fn strip_legacy_numeric(args: &[&str], allow_plus: bool) -> Vec<String> {
    let mut result = Vec::with_capacity(args.len());
    let mut after_separator = false;
    for &arg in args {
        if arg == "--" {
            after_separator = true;
            result.push(arg.to_string());
            continue;
        }
        if !after_separator {
            let is_neg = arg.starts_with('-');
            let is_pos = allow_plus && arg.starts_with('+');
            if (is_neg || is_pos) && arg.len() > 1 {
                let rest = &arg[1..];
                let digit_end = rest
                    .bytes()
                    .position(|b| !b.is_ascii_digit())
                    .unwrap_or(rest.len());
                if digit_end > 0 && rest[digit_end..].bytes().all(|b| b.is_ascii_lowercase()) {
                    continue; // strip this legacy arg
                }
            }
        }
        result.push(arg.to_string());
    }
    result
}

/// Remove the long options naming a program the command will execute, reporting
/// whether any were present.
///
/// GNU `getopt_long` resolves an exact match first and otherwise accepts any
/// *unambiguous abbreviation*, so matching exact spellings alone leaves
/// `--use-compress-prog`, `--use-comp` and even `--use` wide open — verified
/// against GNU tar 1.35, where every one of those executes the program. An
/// argument counts when its long-option name is a **prefix** of an exec-bearing
/// option. That also swallows abbreviations which are ambiguous for the real
/// tool, but those make it error out and do nothing, so the over-approximation
/// costs at most a prompt.
///
/// `non_exec` holds options that are complete spellings in their own right *and*
/// strict prefixes of an exec-bearing one: `tar --checkpoint` against
/// `--checkpoint-action`, `install --strip` against `--strip-program`. An exact
/// match to one of those wins, exactly as `getopt_long` resolves it. Both were
/// derived from the tools' own `--help`, and they are the only two collisions
/// across the commands scriptcheck parses — a new entry belongs here only when
/// the same dump shows one.
///
/// The options are removed rather than merely flagged so that what remains still
/// parses: the invocation keeps its file accesses, and the deny rules covering
/// them keep firing.
///
/// Option parsing stops at `--`, as it does in the tools.
pub(super) fn strip_program_options<'a>(
    args: &[&'a str],
    exec: &[&str],
    non_exec: &[&str],
) -> (Vec<&'a str>, bool) {
    let mut kept: Vec<&str> = Vec::with_capacity(args.len());
    let mut found = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--" {
            kept.extend_from_slice(&args[i..]);
            break;
        }
        let Some(body) = arg.strip_prefix("--") else {
            kept.push(arg);
            i += 1;
            continue;
        };
        let (name, has_inline_value) = match body.split_once('=') {
            Some((name, _)) => (name, true),
            None => (body, false),
        };
        let is_exec = !name.is_empty()
            && !non_exec.contains(&name)
            && exec.iter().any(|option| option.starts_with(name));
        if !is_exec {
            kept.push(arg);
            i += 1;
            continue;
        }
        found = true;
        // Drop the option, and the separate token holding its value if any.
        i += if has_inline_value { 1 } else { 2 };
    }
    (kept, found)
}
