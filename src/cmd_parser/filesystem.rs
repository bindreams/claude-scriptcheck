use crate::file_access::AccessScope;

use clap::{ArgAction, ArgMatches};

use super::helpers::*;
use super::{resolve, resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

// ─── Copy-like commands ──────────────────────────────────────────────────────

/// `cp -r`/`-R`/`-a` walks directory operands; `-L` makes the walk follow
/// symlinks, so it can pull in content from outside the named tree.
fn cp_recursion(matches: &ArgMatches) -> Recursion {
    let recursive = matches.get_count("recursive") > 0
        || matches.get_count("bool_R") > 0
        || matches.get_count("archive") > 0;
    if !recursive {
        Recursion::No
    } else if matches.get_count("dereference") > 0 {
        Recursion::Following
    } else {
        Recursion::Yes
    }
}

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

        let recursion = cp_recursion(&matches);
        parse_copy_like(&matches, cwd, recursion)
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

        parse_copy_like(&matches, cwd, Recursion::IfDir)
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

        parse_copy_like(&matches, cwd, Recursion::No)
    }
}

/// The writes a copy-like command performs on `dest`.
///
/// `cp`/`mv`/`ln`/`install` write to `dest/basename(src)` whenever `dest` is an
/// existing directory, so recording `dest` alone lets the real write slip past
/// a rule scoped to the directory's contents. The directory itself is kept as
/// an access too — its entries change — so rules written against either form
/// still fire.
///
/// Each write inherits the scope of the source it came from: moving a
/// directory writes a whole tree, moving a file writes one path. The
/// destination is never classified by its own `stat`, which would say
/// "does not exist yet" for the common case.
///
/// `force_directory` is for `-t`, which names a directory by definition, and
/// `no_target_directory` is `-T`, which means the destination is the path
/// itself. Otherwise a check-time stat decides, with the same accepted race as
/// `Recursion::IfDir`.
///
/// The two differ on what an unreadable stat means, and deliberately so. A
/// *source* that cannot be stat'd may still be a directory the command walks,
/// so the unknown resolves to the wider scope. A destination that is reported
/// missing provably is not a directory yet — the command creates a plain file
/// there — so that case resolves narrow. Any other stat error leaves the
/// question open and takes the directory branch.
fn copy_destination_writes(
    dest: &str,
    sources: &[&String],
    source_scopes: &[AccessScope],
    cwd: &str,
    force_directory: bool,
    no_target_directory: bool,
) -> Vec<AccessScope> {
    let subtree_source = source_scopes.iter().any(|s| {
        matches!(
            s,
            AccessScope::Subtree(_) | AccessScope::UnboundedSubtree(_)
        )
    });
    let dest_path = super::resolve_str(dest, cwd);

    if no_target_directory {
        return vec![scope_like(subtree_source, dest_path)];
    }

    let is_dir = force_directory
        || match std::fs::metadata(&dest_path) {
            Ok(meta) => meta.is_dir(),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        };
    if !is_dir {
        return vec![scope_like(subtree_source, dest_path)];
    }

    // The directory's own entries change, plus one write per source landing
    // inside it.
    let base = dest_path.trim_end_matches('/').to_string();
    let mut writes = vec![AccessScope::Exact(dest_path)];
    for (i, src) in sources.iter().enumerate() {
        let nested = source_scopes.get(i).is_some_and(|s| {
            matches!(
                s,
                AccessScope::Subtree(_) | AccessScope::UnboundedSubtree(_)
            )
        });
        let name = src.trim_end_matches('/').rsplit(['/', '\\']).next();
        match name {
            // `cp -r src/. dest` copies the source's *contents*, so the writes
            // land directly under `dest` with no single landing path to name.
            Some(".") | Some("..") | Some("") | None => {
                writes.push(AccessScope::Subtree(base.clone()));
            }
            Some(name) => writes.push(scope_like(nested, format!("{base}/{name}"))),
        }
    }
    writes
}

fn scope_like(subtree: bool, path: String) -> AccessScope {
    if subtree {
        AccessScope::Subtree(path)
    } else {
        AccessScope::Exact(path)
    }
}

/// Shared cp/mv/ln extraction:
/// - With -t DIR: all positionals → reads, DIR (and the paths landing inside
///   it) → writes.
/// - Without -t: last positional → writes, rest → reads.
fn parse_copy_like(
    matches: &ArgMatches,
    cwd: &str,
    recursion: Recursion,
) -> Result<CommandFileAccesses, String> {
    let mut reads = Vec::new();
    let mut writes = Vec::new();

    let target_dir = matches.get_one::<String>("target-directory");

    let positionals: Vec<&String> = matches
        .get_many::<String>("files")
        .map(|v| v.collect())
        .unwrap_or_default();

    let no_target_directory = matches.get_count("no-target-directory") > 0;

    if let Some(dir) = target_dir {
        // -t DIR: all positionals are sources (read), DIR is write target
        let scopes: Vec<AccessScope> = positionals
            .iter()
            .map(|p| resolve_scoped(p, cwd, recursion))
            .collect();
        reads.extend(scopes.iter().cloned());
        writes.extend(copy_destination_writes(
            dir,
            &positionals,
            &scopes,
            cwd,
            true,
            false,
        ));
    } else if let Some((last, rest)) = positionals.split_last() {
        let scopes: Vec<AccessScope> = rest
            .iter()
            .map(|src| resolve_scoped(src, cwd, recursion))
            .collect();
        reads.extend(scopes.iter().cloned());
        writes.extend(copy_destination_writes(
            last,
            rest,
            &scopes,
            cwd,
            false,
            no_target_directory,
        ));
    }

    Ok(CommandFileAccesses {
        reads,
        writes,
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    })
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
            let scopes: Vec<AccessScope> = positionals.iter().map(|p| resolve(p, cwd)).collect();
            reads.extend(scopes.iter().cloned());
            writes.extend(copy_destination_writes(
                dir,
                &positionals,
                &scopes,
                cwd,
                true,
                false,
            ));
        } else if let Some((last, rest)) = positionals.split_last() {
            let scopes: Vec<AccessScope> = rest.iter().map(|src| resolve(src, cwd)).collect();
            reads.extend(scopes.iter().cloned());
            writes.extend(copy_destination_writes(
                last,
                rest,
                &scopes,
                cwd,
                false,
                matches.get_count("no-target-directory") > 0,
            ));
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
            args,
            cwd,
            extract_positional_writes,
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
            args,
            cwd,
            extract_positional_writes,
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

        // -r compares two directory trees.
        let recursion = if matches.get_count("recursive") > 0 {
            Recursion::Yes
        } else {
            Recursion::No
        };
        let reads = matches
            .get_many::<String>("files")
            .map(|vals| vals.map(|f| resolve_scoped(f, cwd, recursion)).collect())
            .unwrap_or_default();
        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
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

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            // `--compress-program` runs the named command on every temporary
            // file, which no `Read`/`Write` rule can gate. GNU-only — BSD sort
            // ignores the flag — but treated as exec-capable everywhere,
            // because over-approximating costs a prompt and the alternative
            // leaves the hole.
            file_only: names_a_program(&matches, "compress-program"),
            ..Default::default()
        })
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

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
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

    // -R applies the change to every file beneath each operand; -L/-H make
    // that walk traverse symlinked directories, so it can leave the operand's
    // tree. `chmod` declares neither flag, so the lookups are simply absent there.
    let dereferences = matches
        .try_get_one::<u8>("dereference")
        .ok()
        .flatten()
        .is_some_and(|c| *c > 0)
        || matches
            .try_get_one::<u8>("dereference-command-line")
            .ok()
            .flatten()
            .is_some_and(|c| *c > 0);
    let recursion = if matches.get_count("recursive") == 0 {
        Recursion::No
    } else if dereferences {
        Recursion::Following
    } else {
        Recursion::Yes
    };

    let writes = positionals
        .iter()
        .skip(1) // skip mode/owner/group
        .map(|p| resolve_scoped(p, cwd, recursion))
        .collect();

    Ok(CommandFileAccesses {
        reads: Vec::new(),
        writes,
        inline_script_start: None,
        file_only: None,
        ..Default::default()
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
            file_only: None,
            ..Default::default()
        })
    }
}
