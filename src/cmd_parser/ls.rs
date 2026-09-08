use crate::file_access::AccessScope;

use super::helpers::*;
use super::{resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

// ─── ls ──────────────────────────────────────────────────────────────────────

/// `ls` reads directory entries. `-R` walks the whole subtree; with no operand
/// it lists the working directory.
pub(super) struct LsParser;

impl CommandParser for LsParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("ls")
            // Value-taking
            .arg(val_l("color"))
            .arg(val_l("colour"))
            .arg(val_l("time-style"))
            .arg(val_l("sort"))
            .arg(val_l("time"))
            .arg(val_l("format"))
            .arg(val_l("indicator-style"))
            .arg(val_l("quoting-style"))
            .arg(val_l("hide"))
            .arg(val_l("ignore"))
            .arg(val_l("block-size"))
            .arg(val('I', "ignore-pattern"))
            .arg(val('w', "width"))
            .arg(val('T', "tabsize"))
            // Bool flags
            .arg(flag('l', "long"))
            .arg(flag('a', "all"))
            .arg(flag('A', "almost-all"))
            .arg(flag('R', "recursive"))
            .arg(flag('d', "directory"))
            .arg(flag('h', "human-readable"))
            .arg(flag('t', "sort-time"))
            .arg(flag('S', "sort-size"))
            .arg(flag('r', "reverse"))
            .arg(flag('F', "classify"))
            .arg(flag('i', "inode"))
            .arg(flag('n', "numeric-uid-gid"))
            .arg(flag('p', "slash-dirs"))
            .arg(flag('u', "sort-atime"))
            .arg(flag('c', "sort-ctime"))
            .arg(flag('L', "dereference"))
            .arg(flag('H', "dereference-command-line"))
            .arg(flag('s', "size"))
            .arg(flag('k', "kibibytes"))
            .arg(flag('m', "comma-separated"))
            .arg(flag('x', "sort-across"))
            .arg(flag('C', "columns"))
            .arg(flag('G', "no-group"))
            .arg(flag('o', "long-no-group"))
            .arg(flag('g', "long-no-owner"))
            .arg(flag('U', "unsorted"))
            .arg(flag('f', "unsorted-all"))
            .arg(flag('q', "hide-control-chars"))
            .arg(flag('Q', "quote-name"))
            .arg(flag('b', "escape"))
            .arg(flag('B', "ignore-backups"))
            .arg(flag('v', "version-sort"))
            .arg(flag('X', "sort-extension"))
            .arg(bool_s('1'))
            .arg(bool_s('@'))
            .arg(bool_s('e'))
            .arg(bool_s('O'))
            .arg(bool_s('P'))
            .arg(flag_l("group-directories-first"))
            .arg(flag_l("full-time"))
            .arg(flag_l("si"))
            .arg(flag_l("literal"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let recursion = if matches.get_count("recursive") > 0 {
            Recursion::Yes
        } else {
            Recursion::No
        };

        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let reads: Vec<AccessScope> = if positionals.is_empty() {
            // No operand: `ls` lists the working directory.
            vec![resolve_scoped(cwd, cwd, recursion)]
        } else {
            positionals
                .iter()
                .map(|p| resolve_scoped(p, cwd, recursion))
                .collect()
        };

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
    }
}
