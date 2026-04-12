use super::{resolve, CommandFileAccesses, CommandParser};

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

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
    }
}
