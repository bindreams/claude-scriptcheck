use super::helpers::*;
use super::{resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

// ─── Simple writers ──────────────────────────────────────────────────────────
// All positional args → writes.

pub(super) struct RmParser;
impl CommandParser for RmParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("rm")
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
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let recursion = if matches.get_count("recursive") > 0 || matches.get_count("bool_R") > 0 {
            Recursion::Yes
        } else {
            Recursion::No
        };
        let writes = matches
            .get_many::<String>("files")
            .map(|vals| vals.map(|f| resolve_scoped(f, cwd, recursion)).collect())
            .unwrap_or_default();

        Ok(CommandFileAccesses {
            reads: Vec::new(),
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
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
            args,
            cwd,
            extract_positional_writes,
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
            args,
            cwd,
            extract_positional_writes,
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
            args,
            cwd,
            extract_positional_writes,
        )
    }
}
