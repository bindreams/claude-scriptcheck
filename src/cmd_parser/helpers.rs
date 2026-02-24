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
    }
}

pub(super) fn parse_with(cmd: Command, args: &[&str], cwd: &str, extract: fn(&ArgMatches, &str) -> CommandFileAccesses) -> Result<CommandFileAccesses, String> {
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
                let digit_end = rest.bytes()
                    .position(|b| !b.is_ascii_digit())
                    .unwrap_or(rest.len());
                if digit_end > 0
                    && rest[digit_end..].bytes().all(|b| b.is_ascii_lowercase())
                {
                    continue; // strip this legacy arg
                }
            }
        }
        result.push(arg.to_string());
    }
    result
}
