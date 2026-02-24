use super::helpers::*;
use super::{CommandFileAccesses, CommandParser};

// ─── Simple writers ──────────────────────────────────────────────────────────
// All positional args → writes.

pub(super) struct RmParser;
impl CommandParser for RmParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("rm")
                .arg(flag('r', "recursive"))
                .arg(bool_s('R'))
                .arg(flag('f', "force"))
                .arg(flag('i', "interactive"))
                .arg(bool_s('I'))
                .arg(flag('d', "dir"))
                .arg(flag('v', "verbose"))
                .arg(flag_l("one-file-system"))
                .arg(flag_l("no-preserve-root"))
                .arg(flag_l("preserve-root"))
                // BSD/macOS
                .arg(bool_s('P')) // overwrite before deleting
                .arg(bool_s('W')) // undelete
                .arg(bool_s('x')) // don't cross mount points (BSD)
                .arg(files_arg()),
            args, cwd, extract_positional_writes,
        )
    }
}

pub(super) struct RmdirParser;
impl CommandParser for RmdirParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("rmdir")
                .arg(flag('p', "parents"))
                .arg(flag('v', "verbose"))
                .arg(flag_l("ignore-fail-on-non-empty"))
                .arg(files_arg()),
            args, cwd, extract_positional_writes,
        )
    }
}

pub(super) struct TeeParser;
impl CommandParser for TeeParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("tee")
                .arg(flag('a', "append"))
                .arg(flag('i', "ignore-interrupts"))
                .arg(flag('p', "output-error"))
                .arg(files_arg()),
            args, cwd, extract_positional_writes,
        )
    }
}

pub(super) struct TruncateParser;
impl CommandParser for TruncateParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("truncate")
                .arg(val('s', "size"))
                .arg(val('r', "reference"))
                .arg(flag('c', "no-create"))
                .arg(flag('o', "io-blocks"))
                .arg(files_arg()),
            args, cwd, extract_positional_writes,
        )
    }
}
