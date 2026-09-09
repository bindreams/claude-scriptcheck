use clap::ArgAction;

use super::helpers::*;
use super::{resolve, resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

// ─── zip / unzip ─────────────────────────────────────────────────────────────

/// Long options naming a program `zip` runs to test the finished archive
/// instead of `unzip -tqq`. Matched by prefix — see `strip_program_options`.
const ZIP_PROGRAM_OPTIONS: &[&str] = &["unzip-command"];

/// `zip` short options that take a value. In a bundle the value is the rest of
/// the token, so scanning must stop at one of these rather than keep reading
/// letters: the `TT` in `-nTT` is a suffix list, not `-TT`.
const ZIP_VALUE_SHORTS: &[char] = &['x', 'i', 'b', 't', 'n', 'O', 'z'];

/// Lift `-TT <cmd>` and its long spelling out of `args`, reporting whether one
/// was present.
///
/// `-TT` has to be handled before clap: it is one flag to `zip` but two `-T`s to
/// clap, which would then take the command name as the archive positional. It
/// also bundles — `zip -rTT cmd -T out.zip src` executes `cmd`, verified against
/// Zip 3.0 — so the scan decomposes short bundles rather than matching the
/// `-TT` token whole.
fn strip_unzip_command<'a>(args: &[&'a str]) -> (Vec<&'a str>, bool) {
    let (mut kept, mut found) = strip_program_options(args, ZIP_PROGRAM_OPTIONS, &[]);

    let mut out: Vec<&str> = Vec::with_capacity(kept.len());
    let mut drop_next = false;
    for arg in kept.drain(..) {
        if drop_next {
            drop_next = false; // the command `-TT` named
            continue;
        }
        if bundles_double_t(arg) {
            found = true;
            drop_next = true;
        }
        out.push(arg);
    }
    (out, found)
}

/// Does this short-option bundle contain `TT`?
fn bundles_double_t(arg: &str) -> bool {
    let Some(bundle) = arg.strip_prefix('-') else {
        return false;
    };
    if bundle.starts_with('-') {
        return false; // a long option
    }
    let mut previous_was_t = false;
    for ch in bundle.chars() {
        if previous_was_t && ch == 'T' {
            return true;
        }
        if ZIP_VALUE_SHORTS.contains(&ch) {
            return false; // the rest of the token is this option's value
        }
        previous_was_t = ch == 'T';
    }
    false
}

pub(super) struct ZipParser;
impl CommandParser for ZipParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let (args, runs_a_program) = strip_unzip_command(args);
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
            .arg(bool_s('0'))
            .arg(bool_s('1'))
            .arg(bool_s('2'))
            .arg(bool_s('3'))
            .arg(bool_s('4'))
            .arg(bool_s('5'))
            .arg(bool_s('6'))
            .arg(bool_s('7'))
            .arg(bool_s('8'))
            .arg(bool_s('9'))
            .arg(val('x', "exclude").action(ArgAction::Append))
            .arg(val('i', "include").action(ArgAction::Append))
            .arg(val('b', "temp-path"))
            .arg(val('t', "from-date"))
            .arg(val('n', "suffixes"))
            .arg(bool_s('@'))
            .arg(files_arg())
            .try_get_matches_from(&args)
            .map_err(|e| e.to_string())?;

        let positionals: Vec<&String> = matches
            .get_many::<String>("files")
            .map(|v| v.collect())
            .unwrap_or_default();

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // -r walks directory operands.
        let recursion = if matches.get_count("recurse-paths") > 0 {
            Recursion::Yes
        } else {
            Recursion::No
        };

        // First positional is the archive (write), rest are files to add (read)
        if let Some((archive, sources)) = positionals.split_first() {
            writes.push(resolve(archive, cwd));
            for src in sources {
                reads.push(resolve_scoped(src, cwd, recursion));
            }
        }

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: if runs_a_program { Some(false) } else { None },
            ..Default::default()
        })
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

        // Extraction unpacks a whole tree into -d DIR, or into the working
        // directory when -d is absent.
        let dest = matches
            .get_one::<String>("directory")
            .map(|s| s.as_str())
            .unwrap_or(cwd);
        writes.push(resolve_scoped(dest, cwd, Recursion::Yes));

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
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

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
    }
}

// ─── split / csplit ──────────────────────────────────────────────────────────

pub(super) struct SplitParser;
impl CommandParser for SplitParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        // `--filter=CMD` pipes every output chunk through a shell command
        // instead of writing a file. Stripped before clap so an abbreviation
        // still resolves and the input file access survives.
        let (args, runs_a_program) = strip_program_options(args, &["filter"], &[]);
        let args: &[&str] = &args;
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
            // GNU-only — BSD split has no long options — but treated as
            // exec-capable everywhere, on the same reasoning as `tar -I`.
            file_only: if runs_a_program { Some(false) } else { None },
            ..Default::default()
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
            file_only: None,
            ..Default::default()
        })
    }
}
