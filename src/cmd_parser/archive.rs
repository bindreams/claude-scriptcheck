use clap::ArgAction;

use super::helpers::*;
use super::{resolve, CommandFileAccesses, CommandParser};

// ─── zip / unzip ─────────────────────────────────────────────────────────────

pub(super) struct ZipParser;
impl CommandParser for ZipParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("zip")
            .arg(flag('r', "recurse-paths"))
            .arg(flag('j', "junk-paths"))
            .arg(flag('q', "quiet"))
            .arg(flag('v', "verbose"))
            .arg(flag('u', "update"))
            .arg(flag('f', "freshen"))
            .arg(flag('m', "move"))
            .arg(flag('d', "delete"))
            .arg(flag('T', "test"))
            .arg(flag('y', "symlinks"))
            .arg(flag('e', "encrypt"))
            .arg(flag('g', "grow"))
            .arg(flag_l("filesync"))
            .arg(bool_s('0')).arg(bool_s('1')).arg(bool_s('2'))
            .arg(bool_s('3')).arg(bool_s('4')).arg(bool_s('5'))
            .arg(bool_s('6')).arg(bool_s('7')).arg(bool_s('8'))
            .arg(bool_s('9'))
            .arg(val('x', "exclude").action(ArgAction::Append))
            .arg(val('i', "include").action(ArgAction::Append))
            .arg(val('b', "temp-path"))
            .arg(val('t', "from-date"))
            .arg(val('n', "suffixes"))
            .arg(bool_s('@'))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // First positional is the archive (write), rest are files to add (read)
        if let Some((archive, sources)) = positionals.split_first() {
            writes.push(resolve(archive, cwd));
            for src in sources {
                reads.push(resolve(src, cwd));
            }
        }

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

pub(super) struct UnzipParser;
impl CommandParser for UnzipParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("unzip")
            .arg(val('d', "directory"))
            .arg(val('x', "exclude").action(ArgAction::Append))
            .arg(flag('o', "overwrite"))
            .arg(flag('n', "never-overwrite"))
            .arg(flag('f', "freshen"))
            .arg(flag('u', "update"))
            .arg(flag('q', "quiet"))
            .arg(flag('l', "list"))
            .arg(flag('t', "test"))
            .arg(flag('z', "comment"))
            .arg(flag('v', "verbose"))
            .arg(flag('j', "junk-paths"))
            .arg(flag('C', "case-insensitive"))
            .arg(flag('L', "lowercase"))
            .arg(flag('p', "pipe"))
            .arg(flag('P', "password"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // First positional is the archive (read); rest are file patterns (ignore)
        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();
        if let Some(archive) = positionals.first() {
            reads.push(resolve(archive, cwd));
        }

        // -d DIR → write destination
        if let Some(dir) = matches.get_one::<String>("directory") {
            writes.push(resolve(dir, cwd));
        }

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

// ─── patch ───────────────────────────────────────────────────────────────────

pub(super) struct PatchParser;
impl CommandParser for PatchParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("patch")
            .arg(val('i', "input"))
            .arg(val('o', "output"))
            .arg(val('d', "directory"))
            .arg(val('p', "strip"))
            .arg(val('B', "prefix"))
            .arg(val_l("suffix"))
            .arg(val('D', "ifdef"))
            .arg(val('F', "fuzz"))
            .arg(flag('R', "reverse"))
            .arg(flag('N', "forward"))
            .arg(flag('f', "force"))
            .arg(flag('s', "silent"))
            .arg(flag('E', "remove-empty-files"))
            .arg(flag('b', "backup"))
            .arg(flag('l', "ignore-whitespace"))
            .arg(flag('c', "context"))
            .arg(flag('e', "ed"))
            .arg(flag('n', "normal"))
            .arg(flag('u', "unified"))
            .arg(flag('t', "batch"))
            .arg(flag('v', "version"))
            .arg(flag_l("dry-run"))
            .arg(flag_l("verbose"))
            .arg(flag_l("binary"))
            .arg(flag_l("posix"))
            .arg(flag_l("no-backup-if-mismatch"))
            .arg(flag_l("backup-if-mismatch"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // -i FILE → reads patch file
        if let Some(f) = matches.get_one::<String>("input") {
            reads.push(resolve(f, cwd));
        }
        // -o FILE → writes output
        if let Some(f) = matches.get_one::<String>("output") {
            writes.push(resolve(f, cwd));
        }

        // Positionals: [originalfile [patchfile]]
        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();
        if let Some(original) = positionals.first() {
            writes.push(resolve(original, cwd));
        }
        if let Some(patchfile) = positionals.get(1) {
            reads.push(resolve(patchfile, cwd));
        }

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

// ─── split / csplit ──────────────────────────────────────────────────────────

pub(super) struct SplitParser;
impl CommandParser for SplitParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("split")
            .arg(val('b', "bytes"))
            .arg(val('C', "line-bytes"))
            .arg(val('l', "lines"))
            .arg(val('n', "number"))
            .arg(val('a', "suffix-length"))
            .arg(val_l("additional-suffix"))
            .arg(val_l("filter"))
            .arg(flag('d', "numeric-suffixes"))
            .arg(flag('x', "hex-suffixes"))
            .arg(flag('e', "elide-empty-files"))
            .arg(flag_l("verbose"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        // Positionals: [input [prefix]]. input → reads. prefix is output prefix, skip.
        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let mut reads = Vec::new();
        if let Some(input) = positionals.first() {
            reads.push(resolve(input, cwd));
        }

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
        })
    }
}

pub(super) struct CsplitParser;
impl CommandParser for CsplitParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("csplit")
            .arg(val('f', "prefix"))
            .arg(val('b', "suffix-format"))
            .arg(val('n', "digits"))
            .arg(flag('k', "keep-files"))
            .arg(flag('s', "quiet"))
            .arg(flag('z', "elide-empty-files"))
            .arg(flag_l("suppress-matched"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        // Positionals: input pattern... . Only input (first) → reads.
        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let mut reads = Vec::new();
        if let Some(input) = positionals.first() {
            reads.push(resolve(input, cwd));
        }

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
        })
    }
}
