use clap::{ArgAction, ArgMatches};

use super::helpers::*;
use super::{resolve, CommandFileAccesses, CommandParser};

// ─── Copy-like commands ──────────────────────────────────────────────────────

pub(super) struct CpParser;
impl CommandParser for CpParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("cp")
            .arg(val('t', "target-directory"))
            .arg(flag('T', "no-target-directory"))
            .arg(flag('r', "recursive"))
            .arg(bool_s('R'))
            .arg(flag('f', "force"))
            .arg(flag('i', "interactive"))
            .arg(flag('l', "link"))
            .arg(flag('s', "symbolic-link"))
            .arg(flag('n', "no-clobber"))
            .arg(flag('u', "update"))
            .arg(flag('v', "verbose"))
            .arg(flag('a', "archive"))
            .arg(bool_s('d'))
            .arg(flag('L', "dereference"))
            .arg(bool_s('p'))
            .arg(flag('P', "no-dereference"))
            .arg(flag('x', "one-file-system"))
            .arg(val_l("preserve"))
            .arg(val_l("no-preserve"))
            .arg(val_l("reflink"))
            .arg(val_l("sparse"))
            .arg(val_l("backup"))
            .arg(val('S', "suffix"))
            .arg(flag_l("strip-trailing-slashes"))
            // SELinux
            .arg(bool_s('Z'))
            .arg(val_l("context"))
            // BSD/macOS
            .arg(bool_s('c')) // clone (macOS)
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_copy_like(&matches, cwd)
    }
}

pub(super) struct MvParser;
impl CommandParser for MvParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("mv")
            .arg(val('t', "target-directory"))
            .arg(flag('T', "no-target-directory"))
            .arg(flag('f', "force"))
            .arg(flag('i', "interactive"))
            .arg(flag('n', "no-clobber"))
            .arg(flag('u', "update"))
            .arg(flag('v', "verbose"))
            .arg(val_l("backup"))
            .arg(val('S', "suffix"))
            .arg(flag_l("strip-trailing-slashes"))
            // SELinux
            .arg(bool_s('Z'))
            .arg(val_l("context"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_copy_like(&matches, cwd)
    }
}

pub(super) struct LnParser;
impl CommandParser for LnParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("ln")
            .arg(val('t', "target-directory"))
            .arg(flag('T', "no-target-directory"))
            .arg(flag('s', "symbolic"))
            .arg(flag('f', "force"))
            .arg(flag('i', "interactive"))
            .arg(flag('n', "no-dereference"))
            .arg(flag('r', "relative"))
            .arg(flag('v', "verbose"))
            .arg(flag('L', "logical"))
            .arg(flag('P', "physical"))
            .arg(val_l("backup"))
            .arg(val('S', "suffix"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_copy_like(&matches, cwd)
    }
}

/// Shared cp/mv/ln extraction:
/// - With -t DIR: all positionals → reads, DIR → writes
/// - Without -t: last positional → writes, rest → reads
fn parse_copy_like(matches: &ArgMatches, cwd: &str) -> Result<CommandFileAccesses, String> {
    let mut reads = Vec::new();
    let mut writes = Vec::new();

    let target_dir = matches.get_one::<String>("target-directory");

    let positionals: Vec<&String> = matches
        .get_many::<String>("files")
        .map(|v| v.collect())
        .unwrap_or_default();

    if let Some(dir) = target_dir {
        // -t DIR: all positionals are sources (read), DIR is write target
        for p in &positionals {
            reads.push(resolve(p, cwd));
        }
        writes.push(resolve(dir, cwd));
    } else if let Some((last, rest)) = positionals.split_last() {
        for src in rest {
            reads.push(resolve(src, cwd));
        }
        writes.push(resolve(last, cwd));
    }

    Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
}

pub(super) struct InstallParser;
impl CommandParser for InstallParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("install")
            .arg(flag('d', "directory"))
            .arg(val('t', "target-directory"))
            .arg(val('m', "mode"))
            .arg(val('o', "owner"))
            .arg(val('g', "group"))
            .arg(flag('p', "preserve-timestamps"))
            .arg(flag('s', "strip"))
            .arg(val_l("strip-program"))
            .arg(flag('v', "verbose"))
            .arg(flag('D', "create-leading"))
            .arg(flag('T', "no-target-directory"))
            .arg(flag('C', "compare"))
            .arg(val_l("backup"))
            .arg(val('S', "suffix"))
            // SELinux
            .arg(bool_s('Z'))
            .arg(val_l("context"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let is_dir_mode = matches.get_count("directory") > 0;
        let target_dir = matches.get_one::<String>("target-directory");

        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        if is_dir_mode {
            // -d: all positionals are directories to create
            for p in &positionals {
                writes.push(resolve(p, cwd));
            }
        } else if let Some(dir) = target_dir {
            for p in &positionals {
                reads.push(resolve(p, cwd));
            }
            writes.push(resolve(dir, cwd));
        } else if let Some((last, rest)) = positionals.split_last() {
            for src in rest {
                reads.push(resolve(src, cwd));
            }
            writes.push(resolve(last, cwd));
        }

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

// ─── mkdir / touch ───────────────────────────────────────────────────────────

pub(super) struct MkdirParser;
impl CommandParser for MkdirParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("mkdir")
                .arg(flag('p', "parents"))
                .arg(val('m', "mode"))
                .arg(flag('v', "verbose"))
                // SELinux
                .arg(bool_s('Z'))
                .arg(val_l("context"))
                .arg(files_arg()),
            args, cwd, extract_positional_writes,
        )
    }
}

pub(super) struct TouchParser;
impl CommandParser for TouchParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("touch")
                .arg(flag('a', "time-access"))
                .arg(flag('c', "no-create"))
                .arg(val('d', "date"))
                .arg(flag('m', "time-modify"))
                .arg(val('r', "reference"))
                .arg(val('t', "time"))
                .arg(flag_l("no-dereference"))
                // BSD/macOS
                .arg(bool_s('A'))
                .arg(files_arg()),
            args, cwd, extract_positional_writes,
        )
    }
}

// ─── diff ────────────────────────────────────────────────────────────────────

pub(super) struct DiffParser;
impl CommandParser for DiffParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("diff")
            // Value-taking
            .arg(val('U', "unified"))
            .arg(val('C', "context"))
            .arg(val('I', "ignore-matching-lines"))
            .arg(val_l("label"))
            .arg(val_l("color"))
            .arg(val_l("palette"))
            .arg(val_l("from-file"))
            .arg(val_l("to-file"))
            .arg(val_l("line-format"))
            .arg(val_l("old-line-format"))
            .arg(val_l("new-line-format"))
            .arg(val_l("unchanged-line-format"))
            .arg(val_l("old-group-format"))
            .arg(val_l("new-group-format"))
            .arg(val_l("changed-group-format"))
            .arg(val_l("unchanged-group-format"))
            .arg(val_l("starting-file"))
            .arg(val('F', "show-function-line"))
            .arg(val_l("tabsize"))
            .arg(val_l("horizon-lines"))
            .arg(val('D', "ifdef"))
            .arg(val('x', "exclude"))
            .arg(val('X', "exclude-from"))
            .arg(val('W', "width"))
            // Bool flags
            .arg(flag('r', "recursive"))
            .arg(flag('q', "brief"))
            .arg(flag('s', "report-identical-files"))
            .arg(flag('N', "new-file"))
            .arg(flag('u', "unified-short"))
            .arg(flag('c', "context-short"))
            .arg(flag('y', "side-by-side"))
            .arg(flag('i', "ignore-case"))
            .arg(flag('w', "ignore-all-space"))
            .arg(flag('b', "ignore-space-change"))
            .arg(flag('B', "ignore-blank-lines"))
            .arg(flag('E', "ignore-tab-expansion"))
            .arg(flag('Z', "ignore-trailing-space"))
            .arg(flag('a', "text"))
            .arg(flag('t', "expand-tabs"))
            .arg(flag('T', "initial-tab"))
            .arg(flag('l', "paginate"))
            .arg(flag('p', "show-c-function"))
            .arg(flag('e', "ed"))
            .arg(flag('n', "rcs"))
            .arg(flag_l("normal"))
            .arg(flag_l("left-column"))
            .arg(flag_l("suppress-common-lines"))
            .arg(flag_l("strip-trailing-cr"))
            .arg(flag_l("no-dereference"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        // All positional files are read targets
        Ok(extract_positional_reads(&matches, cwd))
    }
}

// ─── sort ────────────────────────────────────────────────────────────────────

pub(super) struct SortParser;
impl CommandParser for SortParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("sort")
            .arg(val('o', "output"))
            .arg(val('k', "key").action(ArgAction::Append))
            .arg(val('t', "field-separator"))
            .arg(val('T', "temporary-directory"))
            .arg(val('S', "buffer-size"))
            .arg(val_l("parallel"))
            .arg(val_l("batch-size"))
            .arg(val_l("compress-program"))
            .arg(val_l("files0-from"))
            // Bool flags
            .arg(flag('b', "ignore-leading-blanks"))
            .arg(flag('d', "dictionary-order"))
            .arg(flag('f', "ignore-case"))
            .arg(flag('g', "general-numeric-sort"))
            .arg(flag('i', "ignore-nonprinting"))
            .arg(flag('M', "month-sort"))
            .arg(flag('h', "human-numeric-sort"))
            .arg(flag('n', "numeric-sort"))
            .arg(flag('R', "random-sort"))
            .arg(flag('V', "version-sort"))
            .arg(flag('r', "reverse"))
            .arg(flag('c', "check"))
            .arg(flag('C', "check-quiet"))
            .arg(flag('m', "merge"))
            .arg(flag('s', "stable"))
            .arg(flag('u', "unique"))
            .arg(flag('z', "zero-terminated"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let reads = matches
            .get_many::<String>("files")
            .map(|vals| vals.map(|f| resolve(f, cwd)).collect())
            .unwrap_or_default();

        let mut writes = Vec::new();
        if let Some(output) = matches.get_one::<String>("output") {
            writes.push(resolve(output, cwd));
        }

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

// ─── uniq ────────────────────────────────────────────────────────────────────

pub(super) struct UniqParser;
impl CommandParser for UniqParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("uniq")
            .arg(val('f', "skip-fields"))
            .arg(val('s', "skip-chars"))
            .arg(val('w', "check-chars"))
            .arg(flag('c', "count"))
            .arg(flag('d', "repeated"))
            .arg(flag('D', "all-repeated"))
            .arg(flag('u', "unique"))
            .arg(flag('i', "ignore-case"))
            .arg(flag('z', "zero-terminated"))
            .arg(val_l("group"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        // uniq [input [output]]
        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        if let Some(input) = positionals.first() {
            reads.push(resolve(input, cwd));
        }
        if let Some(output) = positionals.get(1) {
            writes.push(resolve(output, cwd));
        }

        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

// ─── chmod / chown / chgrp ───────────────────────────────────────────────────

pub(super) struct ChmodParser;
impl CommandParser for ChmodParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("chmod")
            .arg(flag('R', "recursive"))
            .arg(flag('f', "silent"))
            .arg(flag('v', "verbose"))
            .arg(flag('c', "changes"))
            .arg(val_l("reference"))
            .arg(flag_l("preserve-root"))
            .arg(flag_l("no-preserve-root"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_permission_change(&matches, cwd)
    }
}

pub(super) struct ChownParser;
impl CommandParser for ChownParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("chown")
            .arg(flag('R', "recursive"))
            .arg(flag('f', "silent"))
            .arg(flag('v', "verbose"))
            .arg(flag('c', "changes"))
            .arg(flag('h', "no-dereference"))
            .arg(flag('H', "dereference-command-line"))
            .arg(flag('L', "dereference"))
            .arg(flag('P', "no-dereference-physical"))
            .arg(val_l("from"))
            .arg(val_l("reference"))
            .arg(flag_l("preserve-root"))
            .arg(flag_l("no-preserve-root"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_permission_change(&matches, cwd)
    }
}

pub(super) struct ChgrpParser;
impl CommandParser for ChgrpParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("chgrp")
            .arg(flag('R', "recursive"))
            .arg(flag('f', "silent"))
            .arg(flag('v', "verbose"))
            .arg(flag('c', "changes"))
            .arg(flag('h', "no-dereference"))
            .arg(flag('H', "dereference-command-line"))
            .arg(flag('L', "dereference"))
            .arg(flag('P', "no-dereference-physical"))
            .arg(val_l("reference"))
            .arg(flag_l("preserve-root"))
            .arg(flag_l("no-preserve-root"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_permission_change(&matches, cwd)
    }
}

/// Shared chmod/chown/chgrp: first positional is mode/owner/group (skip), rest are writes.
fn parse_permission_change(matches: &ArgMatches, cwd: &str) -> Result<CommandFileAccesses, String> {
    let positionals: Vec<&String> = matches
        .get_many::<String>("files")
        .map(|v| v.collect())
        .unwrap_or_default();

    let writes = positionals
        .iter()
        .skip(1) // skip mode/owner/group
        .map(|p| resolve(p, cwd))
        .collect();

    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes,
        inline_script_start: None,
    })
}

// ─── source / . ──────────────────────────────────────────────────────────────

pub(super) struct SourceParser;
impl CommandParser for SourceParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        // source FILE [args...] — only first arg is a file to read
        let mut reads = Vec::new();
        if let Some(first) = args.first() {
            reads.push(resolve(first, cwd));
        }
        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
        })
    }
}
