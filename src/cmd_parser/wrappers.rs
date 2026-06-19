use super::{get_parser, normalize_cmd_name, resolve, CommandFileAccesses, CommandParser};

// uv run flags ========================================================================================================

const UV_RUN_VALUE_FLAGS: &[&str] = &[
    "--with",
    "--with-requirements",
    "--directory",
    "--project",
    "--python",
    "--group",
    "--extra",
];

const UV_RUN_BOOL_FLAGS: &[&str] = &[
    "--no-project",
    "--isolated",
    "--frozen",
    "--locked",
    "--no-sync",
    "--all-groups",
    "--no-group",
];

// UvParser ============================================================================================================

pub struct UvParser;

impl CommandParser for UvParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        // Only handle `uv run ...`
        if args.first() != Some(&"run") {
            return Ok(CommandFileAccesses::empty());
        }

        parse_uv_run(&args[1..], cwd)
    }
}

fn parse_uv_run(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
    let mut i = 0;
    let mut consumed_prefix = 1; // account for "run" already consumed

    // Consume uv run flags
    while i < args.len() {
        let arg = args[i];

        if arg == "--" {
            i += 1;
            consumed_prefix += 1;
            break;
        }

        if UV_RUN_VALUE_FLAGS.contains(&arg) {
            if i + 1 >= args.len() {
                return Err(format!("uv run flag {arg} requires a value"));
            }
            i += 2; // flag + value
            consumed_prefix += 2;
            continue;
        }

        if UV_RUN_BOOL_FLAGS.contains(&arg) {
            i += 1;
            consumed_prefix += 1;
            continue;
        }

        // Unrecognized flag → conservative bail-out
        if arg.starts_with('-') {
            // Could be --with=value form
            if let Some((flag, _)) = arg.split_once('=') {
                if UV_RUN_VALUE_FLAGS.contains(&flag) {
                    i += 1;
                    consumed_prefix += 1;
                    continue;
                }
            }
            return Err(format!("unrecognized uv run flag: {arg}"));
        }

        // First positional = inner command
        break;
    }

    if i >= args.len() {
        // `uv run` with no command (interactive/stdin)
        return Ok(CommandFileAccesses::empty());
    }

    let inner_cmd_raw = args[i];
    let inner_cmd = normalize_cmd_name(inner_cmd_raw);
    let inner_args = &args[i + 1..];
    consumed_prefix += 1; // account for the inner command name itself

    // If inner command has a known parser, delegate to it
    if let Some(parser) = get_parser(inner_cmd) {
        let concrete: Vec<&str> = inner_args.to_vec();
        let mut result = parser.parse(&concrete, cwd)?;

        // Adjust inline_script_start to be relative to the full `uv run ...` args
        if let Some(ref mut idx) = result.inline_script_start {
            *idx += consumed_prefix;
        }

        result.effective_cmd_name = Some(inner_cmd.to_string());
        return Ok(result);
    }

    // No known parser — check if inner command looks like a .py file
    if inner_cmd_raw.ends_with(".py") {
        return Ok(CommandFileAccesses {
            reads: vec![resolve(inner_cmd_raw, cwd)],
            effective_cmd_name: Some(inner_cmd.to_string()),
            ..Default::default()
        });
    }

    // Unknown inner command — return empty (no file accesses known)
    Ok(CommandFileAccesses {
        effective_cmd_name: Some(inner_cmd.to_string()),
        ..Default::default()
    })
}
