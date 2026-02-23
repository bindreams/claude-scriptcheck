use clap::{Arg, ArgAction, ArgMatches, Command};

use super::{resolve, CommandFileAccesses, CommandParser};

// ─── Builder helpers ─────────────────────────────────────────────────────────

fn base_cmd(name: &str) -> Command {
    Command::new(name.to_string())
        .no_binary_name(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
}

/// Boolean flag with short form only.
fn bool_s(short: char) -> Arg {
    Arg::new(format!("bool_{short}"))
        .short(short)
        .action(ArgAction::Count)
        .required(false)
}

/// Boolean flag with both short and long forms.
fn flag(short: char, long: &str) -> Arg {
    Arg::new(long.to_string())
        .short(short)
        .long(long.to_string())
        .action(ArgAction::Count)
        .required(false)
}

/// Long-only boolean flag.
fn flag_l(long: &str) -> Arg {
    Arg::new(long.to_string())
        .long(long.to_string())
        .action(ArgAction::Count)
        .required(false)
}

/// Value-taking flag with short form only.
fn val_s(short: char) -> Arg {
    Arg::new(format!("val_{short}"))
        .short(short)
        .num_args(1)
        .action(ArgAction::Append)
        .required(false)
}

/// Value-taking flag with both short and long forms.
fn val(short: char, long: &str) -> Arg {
    Arg::new(long.to_string())
        .short(short)
        .long(long.to_string())
        .num_args(1)
        .action(ArgAction::Append)
        .required(false)
}

/// Long-only value-taking flag.
fn val_l(long: &str) -> Arg {
    Arg::new(long.to_string())
        .long(long.to_string())
        .num_args(1)
        .action(ArgAction::Append)
        .required(false)
}

/// Positional arg for file paths. Clap handles `--` natively, so
/// `rm -- -weird-file` works without `allow_hyphen_values`.
fn files_arg() -> Arg {
    Arg::new("files").num_args(..)
}

/// Extract resolved read paths from the "files" positional.
fn extract_positional_reads(matches: &ArgMatches, cwd: &str) -> CommandFileAccesses {
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
fn extract_positional_writes(matches: &ArgMatches, cwd: &str) -> CommandFileAccesses {
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

fn parse_with(cmd: Command, args: &[&str], cwd: &str, extract: fn(&ArgMatches, &str) -> CommandFileAccesses) -> Result<CommandFileAccesses, String> {
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

// ─── Simple readers ──────────────────────────────────────────────────────────
// All positional args → reads.

pub(super) struct CatParser;
impl CommandParser for CatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("cat")
                .arg(flag('A', "show-all"))
                .arg(flag('b', "number-nonblank"))
                .arg(bool_s('e'))
                .arg(flag('E', "show-ends"))
                .arg(flag('n', "number"))
                .arg(flag('s', "squeeze-blank"))
                .arg(bool_s('t'))
                .arg(flag('T', "show-tabs"))
                .arg(bool_s('u'))
                .arg(flag('v', "show-nonprinting"))
                // BSD/macOS
                .arg(bool_s('l')) // line buffering (BSD)
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct HeadParser;
impl CommandParser for HeadParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let stripped = strip_legacy_numeric(args, false);
        let str_args: Vec<&str> = stripped.iter().map(|s| s.as_str()).collect();
        parse_with(
            base_cmd("head")
                .arg(val('n', "lines"))
                .arg(val('c', "bytes"))
                .arg(flag('q', "quiet"))
                .arg(flag('v', "verbose"))
                .arg(flag('z', "zero-terminated"))
                .arg(files_arg()),
            &str_args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct TailParser;
impl CommandParser for TailParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let stripped = strip_legacy_numeric(args, true);
        let str_args: Vec<&str> = stripped.iter().map(|s| s.as_str()).collect();
        parse_with(
            base_cmd("tail")
                .arg(val('n', "lines"))
                .arg(val('c', "bytes"))
                .arg(flag('f', "follow"))
                .arg(flag('F', "retry"))
                .arg(flag('q', "quiet"))
                .arg(flag('v', "verbose"))
                .arg(flag('z', "zero-terminated"))
                .arg(val_l("pid"))
                .arg(val('s', "sleep-interval"))
                .arg(val_l("max-unchanged-stats"))
                .arg(files_arg()),
            &str_args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct LessParser;
impl CommandParser for LessParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("less")
                .arg(bool_s('N'))
                .arg(bool_s('S'))
                .arg(bool_s('R'))
                .arg(bool_s('r'))
                .arg(bool_s('F'))
                .arg(bool_s('X'))
                .arg(bool_s('i'))
                .arg(bool_s('I'))
                .arg(bool_s('g'))
                .arg(bool_s('G'))
                .arg(bool_s('m'))
                .arg(bool_s('M'))
                .arg(bool_s('n'))
                .arg(bool_s('e'))
                .arg(bool_s('E'))
                .arg(bool_s('f'))
                .arg(bool_s('s'))
                .arg(val_s('x'))
                .arg(val_s('b'))
                .arg(val_s('h'))
                .arg(val_s('j'))
                .arg(val_s('p'))
                .arg(val_s('t'))
                .arg(val_s('y'))
                .arg(val_s('z'))
                .arg(val_s('P'))
                .arg(val_s('o'))
                .arg(val_s('O'))
                .arg(val_s('k'))
                .arg(val_s('D'))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct MoreParser;
impl CommandParser for MoreParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("more")
                .arg(bool_s('d'))
                .arg(bool_s('l'))
                .arg(bool_s('f'))
                .arg(bool_s('p'))
                .arg(bool_s('c'))
                .arg(bool_s('s'))
                .arg(bool_s('u'))
                .arg(val_s('n'))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct WcParser;
impl CommandParser for WcParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("wc")
                .arg(flag('l', "lines"))
                .arg(flag('w', "words"))
                .arg(flag('c', "bytes"))
                .arg(flag('m', "chars"))
                .arg(flag('L', "max-line-length"))
                .arg(val_l("files0-from"))
                .arg(val_l("total"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct FileParser;
impl CommandParser for FileParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("file")
                .arg(flag('b', "brief"))
                .arg(flag('i', "mime"))
                .arg(flag('L', "dereference"))
                .arg(flag('z', "uncompress"))
                .arg(flag('Z', "uncompress-noreport"))
                .arg(flag('0', "print0"))
                .arg(val('m', "magic-file"))
                .arg(val('f', "files-from"))
                .arg(val('F', "separator"))
                .arg(val('e', "exclude"))
                .arg(val_l("extension"))
                .arg(val_l("mime-type"))
                .arg(val_l("mime-encoding"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct StatParser;
impl CommandParser for StatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("stat")
                .arg(flag('L', "dereference"))
                .arg(flag('f', "file-system"))
                .arg(flag('t', "terse"))
                .arg(val('c', "format"))
                .arg(val_l("printf"))
                // BSD/macOS
                .arg(bool_s('x')) // verbose output
                .arg(bool_s('r')) // raw output
                .arg(bool_s('l')) // ls -lT format
                .arg(bool_s('s')) // display in "shell" format
                .arg(bool_s('n')) // suppress newline
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct Md5sumParser;
impl CommandParser for Md5sumParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("md5sum")
                .arg(flag('b', "binary"))
                .arg(flag('c', "check"))
                .arg(flag('t', "text"))
                .arg(flag_l("tag"))
                .arg(flag_l("quiet"))
                .arg(flag_l("status"))
                .arg(flag_l("strict"))
                .arg(flag('w', "warn"))
                .arg(flag_l("ignore-missing"))
                .arg(flag('z', "zero"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct ShasumParser;
impl CommandParser for ShasumParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("shasum")
                .arg(val('a', "algorithm"))
                .arg(flag('b', "binary"))
                .arg(flag('c', "check"))
                .arg(flag('t', "text"))
                .arg(flag_l("tag"))
                .arg(flag_l("strict"))
                .arg(flag('w', "warn"))
                .arg(flag_l("status"))
                .arg(flag_l("quiet"))
                .arg(flag_l("ignore-missing"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct Sha256sumParser;
impl CommandParser for Sha256sumParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("sha256sum")
                .arg(flag('b', "binary"))
                .arg(flag('c', "check"))
                .arg(flag('t', "text"))
                .arg(flag_l("tag"))
                .arg(flag_l("quiet"))
                .arg(flag_l("status"))
                .arg(flag_l("strict"))
                .arg(flag('w', "warn"))
                .arg(flag_l("ignore-missing"))
                .arg(flag('z', "zero"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct XxdParser;
impl CommandParser for XxdParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("xxd")
                .arg(bool_s('r'))
                .arg(bool_s('p'))
                .arg(bool_s('i'))
                .arg(bool_s('u'))
                .arg(bool_s('E'))
                .arg(bool_s('e'))
                .arg(val_s('l'))
                .arg(val_s('s'))
                .arg(val_s('c'))
                .arg(val_s('g'))
                .arg(val_s('o'))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct HexdumpParser;
impl CommandParser for HexdumpParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("hexdump")
                .arg(bool_s('C'))
                .arg(bool_s('b'))
                .arg(bool_s('c'))
                .arg(bool_s('d'))
                .arg(bool_s('o'))
                .arg(bool_s('x'))
                .arg(bool_s('v'))
                .arg(val_s('n'))
                .arg(val_s('s'))
                .arg(val_s('e'))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct StringsParser;
impl CommandParser for StringsParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("strings")
                .arg(flag('a', "all"))
                .arg(val('n', "bytes"))
                .arg(val('t', "radix"))
                .arg(val('e', "encoding"))
                .arg(flag_l("print-file-name"))
                .arg(bool_s('f'))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct ReadelfParser;
impl CommandParser for ReadelfParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("readelf")
                .arg(flag('a', "all"))
                .arg(flag('h', "file-header"))
                .arg(flag('l', "program-headers"))
                .arg(flag('S', "section-headers"))
                .arg(flag('g', "section-groups"))
                .arg(flag('t', "section-details"))
                .arg(flag('e', "headers"))
                .arg(flag('s', "syms"))
                .arg(flag('n', "notes"))
                .arg(flag('r', "relocs"))
                .arg(flag('u', "unwind"))
                .arg(flag('d', "dynamic"))
                .arg(flag('V', "version-info"))
                .arg(flag('A', "arch-specific"))
                .arg(flag('I', "histogram"))
                .arg(flag('W', "wide"))
                .arg(val('p', "string-dump"))
                .arg(val('x', "hex-dump"))
                .arg(val('R', "relocated-dump"))
                .arg(val_l("dyn-syms"))
                .arg(val('D', "use-dynamic"))
                .arg(val('C', "demangle"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct ObjdumpParser;
impl CommandParser for ObjdumpParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("objdump")
                .arg(flag('a', "archive-headers"))
                .arg(flag('f', "file-headers"))
                .arg(flag('h', "section-headers"))
                .arg(flag('x', "all-headers"))
                .arg(flag('d', "disassemble"))
                .arg(flag('D', "disassemble-all"))
                .arg(flag('S', "source"))
                .arg(flag('s', "full-contents"))
                .arg(flag('g', "debugging"))
                .arg(flag('t', "syms"))
                .arg(flag('T', "dynamic-syms"))
                .arg(flag('r', "reloc"))
                .arg(flag('R', "dynamic-reloc"))
                .arg(flag('l', "line-numbers"))
                .arg(flag('C', "demangle"))
                .arg(flag('w', "wide"))
                .arg(flag('z', "disassemble-zeroes"))
                .arg(val('j', "section"))
                .arg(val('M', "disassembler-options"))
                .arg(val('b', "target"))
                .arg(val('m', "architecture"))
                .arg(val_l("start-address"))
                .arg(val_l("stop-address"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct NmParser;
impl CommandParser for NmParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("nm")
                .arg(flag('A', "print-file-name"))
                .arg(flag('a', "debug-syms"))
                .arg(flag('D', "dynamic"))
                .arg(flag('g', "extern-only"))
                .arg(flag('n', "numeric-sort"))
                .arg(flag('p', "no-sort"))
                .arg(flag('r', "reverse-sort"))
                .arg(flag('S', "print-size"))
                .arg(flag('u', "undefined-only"))
                .arg(flag('C', "demangle"))
                .arg(flag('l', "line-numbers"))
                .arg(val('f', "format"))
                .arg(val('t', "radix"))
                .arg(val_l("target"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct LddParser;
impl CommandParser for LddParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("ldd")
                .arg(flag('v', "verbose"))
                .arg(flag('u', "unused"))
                .arg(flag('d', "data-relocs"))
                .arg(flag('r', "function-relocs"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct SizeParser;
impl CommandParser for SizeParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("size")
                .arg(flag('A', "format"))
                .arg(flag('B', "format-bsd"))
                .arg(flag('d', "radix-10"))
                .arg(flag('o', "radix-8"))
                .arg(flag('x', "radix-16"))
                .arg(flag('t', "totals"))
                .arg(val_l("common"))
                .arg(val_l("target"))
                .arg(val_l("radix"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct CutParser;
impl CommandParser for CutParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("cut")
                .arg(val('b', "bytes"))
                .arg(val('c', "characters"))
                .arg(val('d', "delimiter"))
                .arg(val('f', "fields"))
                .arg(flag('s', "only-delimited"))
                .arg(val_l("output-delimiter"))
                .arg(flag_l("complement"))
                .arg(flag('z', "zero-terminated"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

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

// ─── Pattern-then-files ─────────────────────────────────────────────────────

pub(super) struct GrepParser;
impl CommandParser for GrepParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("grep")
            // Pattern/file flags
            .arg(val('e', "regexp").action(ArgAction::Append))
            .arg(val('f', "file").action(ArgAction::Append))
            // Value-taking flags
            .arg(val('m', "max-count"))
            .arg(val('A', "after-context"))
            .arg(val('B', "before-context"))
            .arg(val('C', "context"))
            .arg(val('d', "directories"))
            .arg(val('D', "devices"))
            .arg(val_l("include"))
            .arg(val_l("exclude"))
            .arg(val_l("exclude-from"))
            .arg(val_l("exclude-dir"))
            .arg(val_l("label"))
            .arg(val_l("color"))
            .arg(val_l("colour"))
            .arg(val_l("binary-files"))
            // Bool flags
            .arg(flag('i', "ignore-case"))
            .arg(flag('v', "invert-match"))
            .arg(flag('w', "word-regexp"))
            .arg(flag('x', "line-regexp"))
            .arg(flag('c', "count"))
            .arg(flag('l', "files-with-matches"))
            .arg(flag('L', "files-without-match"))
            .arg(flag('o', "only-matching"))
            .arg(flag('n', "line-number"))
            .arg(flag('H', "with-filename"))
            .arg(flag('h', "no-filename"))
            .arg(flag('q', "quiet"))
            .arg(flag('s', "no-messages"))
            .arg(flag('r', "recursive"))
            .arg(flag('R', "dereference-recursive"))
            .arg(flag('z', "null-data"))
            .arg(flag('Z', "null"))
            .arg(flag('F', "fixed-strings"))
            .arg(flag('E', "extended-regexp"))
            .arg(flag('P', "perl-regexp"))
            .arg(flag('G', "basic-regexp"))
            .arg(flag('T', "initial-tab"))
            .arg(flag('b', "byte-offset"))
            .arg(flag('a', "text"))
            .arg(flag('I', "binary"))
            .arg(flag('U', "binary-unix"))
            .arg(flag_l("line-buffered"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_grep_like(&matches, cwd)
    }
}

pub(super) struct RgParser;
impl CommandParser for RgParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("rg")
            .arg(val('e', "regexp").action(ArgAction::Append))
            .arg(val('f', "file").action(ArgAction::Append))
            .arg(val('m', "max-count"))
            .arg(val('A', "after-context"))
            .arg(val('B', "before-context"))
            .arg(val('C', "context"))
            .arg(val('g', "glob").action(ArgAction::Append))
            .arg(val_l("iglob").action(ArgAction::Append))
            .arg(val('t', "type").action(ArgAction::Append))
            .arg(val('T', "type-not").action(ArgAction::Append))
            .arg(val_l("type-add").action(ArgAction::Append))
            .arg(val_l("type-clear").action(ArgAction::Append))
            .arg(val('j', "threads"))
            .arg(val_l("max-depth"))
            .arg(val_l("max-filesize"))
            .arg(val_l("max-columns"))
            .arg(val_l("color"))
            .arg(val_l("colors").action(ArgAction::Append))
            .arg(val_l("encoding"))
            .arg(val_l("replace"))
            .arg(val_l("path-separator"))
            .arg(val_l("sort"))
            .arg(val_l("sortr"))
            .arg(val_l("pre"))
            .arg(val_l("pre-glob").action(ArgAction::Append))
            .arg(val_l("engine"))
            .arg(val_l("binary"))
            // Bool flags (common subset)
            .arg(flag('i', "ignore-case"))
            .arg(flag('v', "invert-match"))
            .arg(flag('w', "word-regexp"))
            .arg(flag('x', "line-regexp"))
            .arg(flag('c', "count"))
            .arg(flag('l', "files-with-matches"))
            .arg(flag_l("files-without-match"))
            .arg(flag('o', "only-matching"))
            .arg(flag('n', "line-number"))
            .arg(flag('N', "no-line-number"))
            .arg(flag('H', "with-filename"))
            .arg(flag_l("no-filename"))
            .arg(flag('q', "quiet"))
            .arg(flag('s', "no-messages"))
            .arg(flag('r', "no-require-git"))
            .arg(flag('F', "fixed-strings"))
            .arg(flag('P', "pcre2"))
            .arg(flag('S', "smart-case"))
            .arg(flag('z', "search-zip"))
            .arg(flag('L', "follow"))
            .arg(flag_l("hidden"))
            .arg(flag('p', "pretty"))
            .arg(flag('a', "text"))
            .arg(flag_l("no-heading"))
            .arg(flag_l("heading"))
            .arg(flag_l("vimgrep"))
            .arg(flag_l("json"))
            .arg(flag_l("trim"))
            .arg(flag_l("no-unicode"))
            .arg(flag('U', "multiline"))
            .arg(flag_l("multiline-dotall"))
            .arg(flag_l("crlf"))
            .arg(flag_l("null-data"))
            .arg(flag_l("one-file-system"))
            .arg(flag_l("no-ignore"))
            .arg(flag_l("no-ignore-dot"))
            .arg(flag_l("no-ignore-parent"))
            .arg(flag_l("no-ignore-vcs"))
            .arg(flag_l("no-ignore-global"))
            .arg(flag_l("no-ignore-exclude"))
            .arg(flag('0', "null"))
            .arg(flag_l("count-matches"))
            .arg(flag_l("debug"))
            .arg(flag_l("stats"))
            .arg(flag_l("block-buffered"))
            .arg(flag_l("line-buffered"))
            .arg(flag_l("no-config"))
            .arg(flag_l("no-ignore-messages"))
            .arg(flag_l("passthru"))
            .arg(flag_l("pcre2-unicode"))
            .arg(flag_l("auto-hybrid-regex"))
            .arg(flag_l("byte-offset"))
            .arg(flag_l("list-files"))
            .arg(flag_l("type-list"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        parse_grep_like(&matches, cwd)
    }
}

/// Shared grep/rg extraction: if -e was given, all positionals are files;
/// otherwise first positional is pattern (skipped), rest are files.
/// -f FILE is always a read access.
fn parse_grep_like(matches: &ArgMatches, cwd: &str) -> Result<CommandFileAccesses, String> {
    let mut reads = Vec::new();

    // -f FILE → read access
    if let Some(files) = matches.get_many::<String>("file") {
        for f in files {
            reads.push(resolve(f, cwd));
        }
    }

    let has_e = matches.get_many::<String>("regexp").is_some();
    let has_f = matches.get_many::<String>("file").is_some();
    let explicit_pattern = has_e || has_f;

    if let Some(positionals) = matches.get_many::<String>("files") {
        let positionals: Vec<&String> = positionals.collect();
        if explicit_pattern {
            // -e or -f was given, so all positionals are files
            for p in &positionals {
                reads.push(resolve(p, cwd));
            }
        } else {
            // First positional is pattern (skip), rest are files
            for p in positionals.iter().skip(1) {
                reads.push(resolve(p, cwd));
            }
        }
    }

    Ok(CommandFileAccesses {
        reads,
        writes: Vec::new(),
        inline_script_start: None,
    })
}

pub(super) struct AwkParser;
impl CommandParser for AwkParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("awk")
            .arg(val('f', "file").action(ArgAction::Append))
            .arg(val('F', "field-separator"))
            .arg(val('v', "assign").action(ArgAction::Append))
            .arg(flag_l("posix"))
            .arg(flag_l("traditional"))
            .arg(flag_l("re-interval"))
            .arg(flag('b', "characters-as-bytes"))
            .arg(flag('N', "use-lc-numeric"))
            .arg(val_l("sandbox"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();

        // -f FILE → read access (script file)
        if let Some(files) = matches.get_many::<String>("file") {
            for f in files {
                reads.push(resolve(f, cwd));
            }
        }

        let has_f = matches.get_many::<String>("file").is_some();

        if let Some(positionals) = matches.get_many::<String>("files") {
            let positionals: Vec<&String> = positionals.collect();
            if has_f {
                // All positionals are data files
                for p in &positionals {
                    reads.push(resolve(p, cwd));
                }
            } else {
                // First positional is inline program (skip), rest are data files
                for p in positionals.iter().skip(1) {
                    reads.push(resolve(p, cwd));
                }
            }
        }

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
        })
    }
}

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

// ─── Additional simple readers ───────────────────────────────────────────────

pub(super) struct TacParser;
impl CommandParser for TacParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("tac")
                .arg(flag('b', "before"))
                .arg(flag('r', "regex"))
                .arg(val('s', "separator"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct NlParser;
impl CommandParser for NlParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("nl")
                .arg(val('b', "body-numbering"))
                .arg(val('d', "section-delimiter"))
                .arg(val('f', "footer-numbering"))
                .arg(val('h', "header-numbering"))
                .arg(val('i', "line-increment"))
                .arg(val('l', "join-blank-lines"))
                .arg(val('n', "number-format"))
                .arg(flag('p', "no-renumber"))
                .arg(val('s', "number-separator"))
                .arg(val('v', "starting-line-number"))
                .arg(val('w', "number-width"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct PasteParser;
impl CommandParser for PasteParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("paste")
                .arg(val('d', "delimiters"))
                .arg(flag('s', "serial"))
                .arg(flag('z', "zero-terminated"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct RevParser;
impl CommandParser for RevParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(base_cmd("rev").arg(files_arg()), args, cwd, extract_positional_reads)
    }
}

pub(super) struct ExpandParser;
impl CommandParser for ExpandParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("expand")
                .arg(val('t', "tabs"))
                .arg(flag('i', "initial"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct UnexpandParser;
impl CommandParser for UnexpandParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("unexpand")
                .arg(val('t', "tabs"))
                .arg(flag('a', "all"))
                .arg(flag_l("first-only"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct FoldParser;
impl CommandParser for FoldParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("fold")
                .arg(val('w', "width"))
                .arg(flag('b', "bytes"))
                .arg(flag('s', "spaces"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct ColumnParser;
impl CommandParser for ColumnParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("column")
                .arg(flag('t', "table"))
                .arg(val('s', "separator"))
                .arg(val('o', "output-separator"))
                .arg(val('c', "columns"))
                .arg(val('N', "table-columns"))
                .arg(val('R', "table-right"))
                .arg(val('W', "table-wrap"))
                .arg(val('H', "table-hide"))
                .arg(val('O', "table-order"))
                .arg(val('E', "table-empty"))
                .arg(flag('n', "table-name"))
                .arg(flag('e', "table-noextreme"))
                .arg(flag('x', "fillrows"))
                .arg(flag('r', "tree"))
                .arg(flag('J', "json"))
                .arg(val('l', "table-truncate"))
                .arg(val('d', "table-noheadings"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct OdParser;
impl CommandParser for OdParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("od")
                .arg(val('A', "address-radix"))
                .arg(val('t', "format"))
                .arg(val('j', "skip-bytes"))
                .arg(val('N', "read-bytes"))
                .arg(val('w', "width"))
                .arg(val('S', "strings"))
                .arg(flag('v', "output-duplicates"))
                .arg(bool_s('a'))
                .arg(bool_s('b'))
                .arg(bool_s('c'))
                .arg(bool_s('d'))
                .arg(bool_s('f'))
                .arg(bool_s('i'))
                .arg(bool_s('l'))
                .arg(bool_s('o'))
                .arg(bool_s('s'))
                .arg(bool_s('x'))
                .arg(flag_l("traditional"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct ZcatParser;
impl CommandParser for ZcatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("zcat").arg(flag('f', "force")).arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct BzcatParser;
impl CommandParser for BzcatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("bzcat").arg(flag('s', "small")).arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct XzcatParser;
impl CommandParser for XzcatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(base_cmd("xzcat").arg(files_arg()), args, cwd, extract_positional_reads)
    }
}

pub(super) struct ReadlinkParser;
impl CommandParser for ReadlinkParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("readlink")
                .arg(flag('f', "canonicalize"))
                .arg(flag('e', "canonicalize-existing"))
                .arg(flag('m', "canonicalize-missing"))
                .arg(flag('n', "no-newline"))
                .arg(flag('v', "verbose"))
                .arg(flag('z', "zero"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct DuParser;
impl CommandParser for DuParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("du")
                .arg(flag('a', "all"))
                .arg(flag('s', "summarize"))
                .arg(flag('c', "total"))
                .arg(flag('h', "human-readable"))
                .arg(flag('H', "si"))
                .arg(flag('k', "kilobytes"))
                .arg(flag('m', "megabytes"))
                .arg(flag('l', "count-links"))
                .arg(flag('L', "dereference"))
                .arg(flag('S', "separate-dirs"))
                .arg(flag('x', "one-file-system"))
                .arg(flag('0', "null"))
                .arg(flag_l("apparent-size"))
                .arg(flag_l("inodes"))
                .arg(val('d', "max-depth"))
                .arg(val('B', "block-size"))
                .arg(val_l("exclude"))
                .arg(val('t', "threshold"))
                .arg(val_l("time"))
                .arg(val_l("time-style"))
                .arg(val_l("files0-from"))
                // BSD/macOS
                .arg(val('I', "ignore"))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

pub(super) struct LsofParser;
impl CommandParser for LsofParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("lsof")
                .arg(val_s('c'))
                .arg(val_s('d'))
                .arg(val_s('D'))
                .arg(val_s('g'))
                .arg(val_s('i'))
                .arg(val_s('k'))
                .arg(val_s('p'))
                .arg(val_s('s'))
                .arg(val_s('S'))
                .arg(val_s('T'))
                .arg(val_s('u'))
                .arg(bool_s('a'))
                .arg(bool_s('b'))
                .arg(bool_s('l'))
                .arg(bool_s('n'))
                .arg(bool_s('N'))
                .arg(bool_s('P'))
                .arg(bool_s('R'))
                .arg(bool_s('t'))
                .arg(bool_s('U'))
                .arg(bool_s('V'))
                .arg(bool_s('w'))
                .arg(bool_s('X'))
                .arg(files_arg()),
            args, cwd, extract_positional_reads,
        )
    }
}

// ─── Additional simple writer ────────────────────────────────────────────────

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

// ─── jq (pattern-then-files) ────────────────────────────────────────────────

pub(super) struct JqParser;
impl CommandParser for JqParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("jq")
            // Bool flags
            .arg(flag('r', "raw-output"))
            .arg(flag('R', "raw-input"))
            .arg(flag('S', "sort-keys"))
            .arg(flag('e', "exit-status"))
            .arg(flag('s', "slurp"))
            .arg(flag('c', "compact-output"))
            .arg(flag('j', "join-output"))
            .arg(flag('n', "null-input"))
            .arg(bool_s('0'))
            .arg(flag_l("tab"))
            .arg(flag_l("jsonargs"))
            .arg(flag_l("args"))
            .arg(flag_l("seq"))
            .arg(flag_l("raw-output0"))
            // Value flags
            .arg(val_l("indent"))
            .arg(Arg::new("arg".to_string()).long("arg".to_string()).num_args(2).action(ArgAction::Append).required(false))
            .arg(Arg::new("argjson".to_string()).long("argjson".to_string()).num_args(2).action(ArgAction::Append).required(false))
            .arg(Arg::new("slurpfile".to_string()).long("slurpfile".to_string()).num_args(2).action(ArgAction::Append).required(false))
            .arg(Arg::new("rawfile".to_string()).long("rawfile".to_string()).num_args(2).action(ArgAction::Append).required(false))
            .arg(val_l("from-file"))
            .arg(val('L', "library-path"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();

        // --slurpfile NAME FILE and --rawfile NAME FILE → FILE (2nd value) is a read
        for flag_name in &["slurpfile", "rawfile"] {
            if let Some(vals) = matches.get_many::<String>(*flag_name) {
                let vals: Vec<&String> = vals.collect();
                // Values come in pairs: [name, file, name, file, ...]
                for chunk in vals.chunks(2) {
                    if let Some(file) = chunk.get(1) {
                        reads.push(resolve(file, cwd));
                    }
                }
            }
        }

        // --from-file FILE → reads the jq program from FILE
        let has_from_file = matches.get_one::<String>("from-file").is_some();
        if let Some(f) = matches.get_one::<String>("from-file") {
            reads.push(resolve(f, cwd));
        }

        if let Some(positionals) = matches.get_many::<String>("files") {
            let positionals: Vec<&String> = positionals.collect();
            if has_from_file {
                // All positionals are data files
                for p in &positionals {
                    reads.push(resolve(p, cwd));
                }
            } else {
                // First positional is filter (skip), rest are data files
                for p in positionals.iter().skip(1) {
                    reads.push(resolve(p, cwd));
                }
            }
        }

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
        })
    }
}

// ─── Compression commands ────────────────────────────────────────────────────

/// Shared extraction for gzip/bzip2/xz family:
/// With -c/--stdout/--to-stdout → reads (output to stdout).
/// Without → writes (in-place modification).
fn parse_compression(matches: &ArgMatches, cwd: &str) -> CommandFileAccesses {
    let to_stdout = matches.get_count("stdout") > 0;

    let paths: Vec<String> = matches
        .get_many::<String>("files")
        .map(|vals| vals.map(|f| resolve(f, cwd)).collect())
        .unwrap_or_default();

    if to_stdout {
        CommandFileAccesses { reads: paths, writes: Vec::new(), inline_script_start: None }
    } else {
        CommandFileAccesses { reads: Vec::new(), writes: paths, inline_script_start: None }
    }
}

pub(super) struct GzipParser;
impl CommandParser for GzipParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("gzip")
            .arg(flag('c', "stdout").alias("to-stdout"))
            .arg(flag('d', "decompress"))
            .arg(flag('f', "force"))
            .arg(flag('k', "keep"))
            .arg(flag('l', "list"))
            .arg(flag('n', "no-name"))
            .arg(flag('N', "name"))
            .arg(flag('q', "quiet"))
            .arg(flag('r', "recursive"))
            .arg(flag('t', "test"))
            .arg(flag('v', "verbose"))
            .arg(bool_s('1')).arg(bool_s('2')).arg(bool_s('3'))
            .arg(bool_s('4')).arg(bool_s('5')).arg(bool_s('6'))
            .arg(bool_s('7')).arg(bool_s('8')).arg(bool_s('9'))
            .arg(flag_l("best")).arg(flag_l("fast"))
            .arg(val('S', "suffix"))
            .arg(val_l("rsyncable"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;
        Ok(parse_compression(&matches, cwd))
    }
}

pub(super) struct GunzipParser;
impl CommandParser for GunzipParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        // gunzip is gzip -d — same flags
        GzipParser.parse(args, cwd)
    }
}

pub(super) struct Bzip2Parser;
impl CommandParser for Bzip2Parser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("bzip2")
            .arg(flag('c', "stdout").alias("to-stdout"))
            .arg(flag('d', "decompress"))
            .arg(flag('z', "compress"))
            .arg(flag('f', "force"))
            .arg(flag('k', "keep"))
            .arg(flag('q', "quiet"))
            .arg(flag('s', "small"))
            .arg(flag('t', "test"))
            .arg(flag('v', "verbose"))
            .arg(bool_s('1')).arg(bool_s('2')).arg(bool_s('3'))
            .arg(bool_s('4')).arg(bool_s('5')).arg(bool_s('6'))
            .arg(bool_s('7')).arg(bool_s('8')).arg(bool_s('9'))
            .arg(flag_l("best")).arg(flag_l("fast"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;
        Ok(parse_compression(&matches, cwd))
    }
}

pub(super) struct Bunzip2Parser;
impl CommandParser for Bunzip2Parser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        Bzip2Parser.parse(args, cwd)
    }
}

pub(super) struct XzParser;
impl CommandParser for XzParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("xz")
            .arg(flag('c', "stdout").alias("to-stdout"))
            .arg(flag('d', "decompress"))
            .arg(flag('z', "compress"))
            .arg(flag('f', "force"))
            .arg(flag('k', "keep"))
            .arg(flag('l', "list"))
            .arg(flag('q', "quiet"))
            .arg(flag('t', "test"))
            .arg(flag('v', "verbose"))
            .arg(flag('e', "extreme"))
            .arg(bool_s('0')).arg(bool_s('1')).arg(bool_s('2'))
            .arg(bool_s('3')).arg(bool_s('4')).arg(bool_s('5'))
            .arg(bool_s('6')).arg(bool_s('7')).arg(bool_s('8'))
            .arg(bool_s('9'))
            .arg(flag_l("best")).arg(flag_l("fast"))
            .arg(val('T', "threads"))
            .arg(val('M', "memlimit"))
            .arg(val('F', "format"))
            .arg(val('S', "suffix"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;
        Ok(parse_compression(&matches, cwd))
    }
}

pub(super) struct UnxzParser;
impl CommandParser for UnxzParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        XzParser.parse(args, cwd)
    }
}

// ─── curl / wget ─────────────────────────────────────────────────────────────

pub(super) struct CurlParser;
impl CommandParser for CurlParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("curl")
            // File-producing flags
            .arg(val('o', "output").action(ArgAction::Append))
            .arg(flag('O', "remote-name"))
            .arg(val('c', "cookie-jar"))
            .arg(val('D', "dump-header"))
            .arg(val_l("output-dir"))
            // File-reading flags
            .arg(val('K', "config"))
            .arg(val('b', "cookie"))
            .arg(val('d', "data").action(ArgAction::Append))
            .arg(val_l("data-binary").action(ArgAction::Append))
            .arg(val_l("data-raw").action(ArgAction::Append))
            .arg(val_l("data-urlencode").action(ArgAction::Append))
            .arg(val('T', "upload-file").action(ArgAction::Append))
            .arg(val('F', "form").action(ArgAction::Append))
            .arg(val('E', "cert"))
            .arg(val_l("key"))
            .arg(val_l("cacert"))
            .arg(val_l("capath"))
            // Common value-taking flags (not file-related)
            .arg(val('H', "header").action(ArgAction::Append))
            .arg(val('X', "request"))
            .arg(val('u', "user"))
            .arg(val('A', "user-agent"))
            .arg(val('e', "referer"))
            .arg(val('m', "max-time"))
            .arg(val_l("connect-timeout"))
            .arg(val_l("retry"))
            .arg(val_l("retry-delay"))
            .arg(val_l("retry-max-time"))
            .arg(val('w', "write-out"))
            .arg(val('x', "proxy"))
            .arg(val('U', "proxy-user"))
            .arg(val_l("resolve").action(ArgAction::Append))
            .arg(val_l("interface"))
            .arg(val_l("dns-servers"))
            .arg(val_l("max-redirs"))
            .arg(val_l("limit-rate"))
            .arg(val_l("max-filesize"))
            .arg(val_l("proto"))
            .arg(val_l("range"))
            .arg(val('Y', "speed-limit"))
            .arg(val('y', "speed-time"))
            .arg(val_l("ciphers"))
            .arg(val_l("tls-max"))
            .arg(val_l("tlsv1"))
            // Bool flags
            .arg(flag('f', "fail"))
            .arg(flag('I', "head"))
            .arg(flag('i', "include"))
            .arg(flag('k', "insecure"))
            .arg(flag('L', "location"))
            .arg(flag('s', "silent"))
            .arg(flag('S', "show-error"))
            .arg(flag('v', "verbose"))
            .arg(flag('g', "globoff"))
            .arg(flag('G', "get"))
            .arg(flag('N', "no-buffer"))
            .arg(flag('n', "netrc"))
            .arg(flag('q', "disable"))
            .arg(flag('Z', "parallel"))
            .arg(flag('#', "progress-bar"))
            .arg(flag('C', "continue-at"))
            .arg(flag_l("compressed"))
            .arg(flag_l("create-dirs"))
            .arg(flag_l("fail-early"))
            .arg(flag_l("fail-with-body"))
            .arg(flag_l("http1.1"))
            .arg(flag_l("http2"))
            .arg(flag_l("no-keepalive"))
            .arg(flag_l("raw"))
            .arg(flag_l("tcp-nodelay"))
            .arg(flag_l("tr-encoding"))
            .arg(flag_l("no-progress-meter"))
            .arg(flag_l("no-sessionid"))
            .arg(flag_l("ssl"))
            .arg(flag_l("ssl-reqd"))
            .arg(flag_l("tlsv1.0"))
            .arg(flag_l("tlsv1.1"))
            .arg(flag_l("tlsv1.2"))
            .arg(flag_l("tlsv1.3"))
            .arg(flag_l("sslv2"))
            .arg(flag_l("sslv3"))
            .arg(flag_l("path-as-is"))
            .arg(flag_l("remote-header-name"))
            .arg(flag_l("remote-name-all"))
            .arg(flag_l("tcp-fastopen"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // -o FILE → writes
        if let Some(files) = matches.get_many::<String>("output") {
            for f in files {
                writes.push(resolve(f, cwd));
            }
        }
        // -c FILE → writes (cookie jar)
        if let Some(f) = matches.get_one::<String>("cookie-jar") {
            writes.push(resolve(f, cwd));
        }
        // -D FILE → writes (dump header)
        if let Some(f) = matches.get_one::<String>("dump-header") {
            writes.push(resolve(f, cwd));
        }
        // -T FILE → reads (upload)
        if let Some(files) = matches.get_many::<String>("upload-file") {
            for f in files {
                reads.push(resolve(f, cwd));
            }
        }
        // -K FILE → reads (config)
        if let Some(f) = matches.get_one::<String>("config") {
            reads.push(resolve(f, cwd));
        }

        // Positionals are URLs — ignore them
        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

pub(super) struct WgetParser;
impl CommandParser for WgetParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("wget")
            // File flags
            .arg(val('O', "output-document"))
            .arg(val('P', "directory-prefix"))
            .arg(val('i', "input-file"))
            .arg(val('a', "append-output"))
            .arg(val_l("post-file"))
            .arg(val_l("load-cookies"))
            .arg(val_l("save-cookies"))
            .arg(val_l("body-file"))
            .arg(val_l("ca-certificate"))
            .arg(val_l("certificate"))
            .arg(val_l("private-key"))
            // Common value-taking
            .arg(val('o', "output-file"))
            .arg(val('U', "user-agent"))
            .arg(val_l("header").action(ArgAction::Append))
            .arg(val_l("post-data"))
            .arg(val_l("body-data"))
            .arg(val_l("method"))
            .arg(val_l("user"))
            .arg(val_l("password"))
            .arg(val_l("http-user"))
            .arg(val_l("http-password"))
            .arg(val_l("proxy"))
            .arg(val_l("proxy-user"))
            .arg(val_l("proxy-password"))
            .arg(val_l("referer"))
            .arg(val('e', "execute").action(ArgAction::Append))
            .arg(val('Q', "quota"))
            .arg(val_l("limit-rate"))
            .arg(val('w', "wait"))
            .arg(val_l("waitretry"))
            .arg(val('t', "tries"))
            .arg(val('T', "timeout"))
            .arg(val_l("dns-timeout"))
            .arg(val_l("connect-timeout"))
            .arg(val_l("read-timeout"))
            .arg(val('l', "level"))
            .arg(val('A', "accept").action(ArgAction::Append))
            .arg(val('R', "reject").action(ArgAction::Append))
            .arg(val('D', "domains"))
            .arg(val_l("exclude-domains"))
            .arg(val_l("include-directories"))
            .arg(val_l("exclude-directories"))
            .arg(val_l("cut-dirs"))
            // Bool flags
            .arg(flag('q', "quiet"))
            .arg(flag('v', "verbose"))
            .arg(flag('c', "continue"))
            .arg(flag('N', "timestamping"))
            .arg(flag('S', "server-response"))
            .arg(flag('r', "recursive"))
            .arg(flag('p', "page-requisites"))
            .arg(flag('k', "convert-links"))
            .arg(flag('K', "backup-converted"))
            .arg(flag('m', "mirror"))
            .arg(flag('E', "adjust-extension"))
            .arg(flag('H', "span-hosts"))
            .arg(flag_l("no-check-certificate"))
            .arg(flag_l("no-clobber"))
            .arg(flag_l("no-directories"))
            .arg(flag_l("force-directories"))
            .arg(flag_l("no-host-directories"))
            .arg(flag_l("no-parent"))
            .arg(flag_l("content-disposition"))
            .arg(flag_l("trust-server-names"))
            .arg(flag_l("no-verbose"))
            .arg(flag_l("spider"))
            .arg(flag('b', "background"))
            .arg(bool_s('x'))
            .arg(flag('F', "force-html"))
            .arg(flag_l("delete-after"))
            .arg(flag_l("no-proxy"))
            .arg(flag_l("no-dns-cache"))
            .arg(flag_l("no-cache"))
            .arg(flag_l("no-cookies"))
            .arg(flag_l("keep-session-cookies"))
            .arg(flag_l("inet4-only"))
            .arg(flag_l("inet6-only"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        if let Some(f) = matches.get_one::<String>("output-document") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("directory-prefix") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("append-output") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("save-cookies") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("input-file") {
            reads.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("post-file") {
            reads.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("load-cookies") {
            reads.push(resolve(f, cwd));
        }

        // Positionals are URLs — ignore
        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

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

// ─── Tests ───────────────────────────────────────────────────────────────────
