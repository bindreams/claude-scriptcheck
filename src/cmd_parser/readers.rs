use super::helpers::*;
use super::{resolve, CommandFileAccesses, CommandParser};

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
            args,
            cwd,
            extract_positional_reads,
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
            &str_args,
            cwd,
            extract_positional_reads,
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
            &str_args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
        )
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

pub(super) struct RevParser;
impl CommandParser for RevParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("rev").arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

pub(super) struct ZcatParser;
impl CommandParser for ZcatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("zcat").arg(flag('f', "force")).arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

pub(super) struct BzcatParser;
impl CommandParser for BzcatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("bzcat").arg(flag('s', "small")).arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

pub(super) struct XzcatParser;
impl CommandParser for XzcatParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("xzcat").arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
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
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

// ── base64 (macOS: -i/-o; GNU: positional file) ──

pub(super) struct Base64Parser;
impl CommandParser for Base64Parser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let cmd = base_cmd("base64")
            .arg(flag('d', "decode"))
            .arg(bool_s('D')) // macOS decode alias
            .arg(val('b', "break"))
            .arg(val('i', "input"))
            .arg(val('o', "output"))
            .arg(val('w', "wrap")) // GNU --wrap=COLS
            .arg(flag_l("ignore-garbage"))
            .arg(files_arg());
        let matches = cmd.try_get_matches_from(args).map_err(|e| e.to_string())?;

        let mut reads: Vec<String> = matches
            .get_many::<String>("files")
            .into_iter()
            .flatten()
            .map(|f| resolve(f, cwd))
            .collect();
        if let Some(vals) = matches.get_many::<String>("input") {
            reads.extend(vals.map(|f| resolve(f, cwd)));
        }
        let writes: Vec<String> = matches
            .get_many::<String>("output")
            .into_iter()
            .flatten()
            .map(|f| resolve(f, cwd))
            .collect();

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
    }
}

// ── sha*sum family (all identical flag sets, read-only) ──

macro_rules! shasum_parser {
    ($name:ident, $cmd:expr) => {
        pub(super) struct $name;
        impl CommandParser for $name {
            fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
                parse_with(
                    base_cmd($cmd)
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
                    args,
                    cwd,
                    extract_positional_reads,
                )
            }
        }
    };
}

shasum_parser!(Sha1sumParser, "sha1sum");
shasum_parser!(Sha512sumParser, "sha512sum");
shasum_parser!(Sha224sumParser, "sha224sum");
shasum_parser!(Sha384sumParser, "sha384sum");

// ── b2sum (BLAKE2) ──

pub(super) struct B2sumParser;
impl CommandParser for B2sumParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("b2sum")
                .arg(flag('c', "check"))
                .arg(flag_l("tag"))
                .arg(flag_l("quiet"))
                .arg(flag_l("status"))
                .arg(flag_l("strict"))
                .arg(flag('w', "warn"))
                .arg(flag_l("ignore-missing"))
                .arg(val('l', "length"))
                .arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

// ── cksum / sum ──

pub(super) struct CksumParser;
impl CommandParser for CksumParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("cksum")
                .arg(val_l("algorithm"))
                .arg(flag_l("untagged"))
                .arg(flag_l("raw"))
                .arg(flag_l("base64"))
                .arg(val('l', "length"))
                .arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

pub(super) struct SumParser;
impl CommandParser for SumParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("sum")
                .arg(bool_s('r'))
                .arg(bool_s('s'))
                .arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

// ── md5 (macOS — distinct from GNU md5sum) ──

pub(super) struct Md5Parser;
impl CommandParser for Md5Parser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("md5")
                .arg(bool_s('r')) // reverse output format
                .arg(bool_s('p')) // passthrough (echo stdin)
                .arg(bool_s('q')) // quiet
                .arg(val('s', "string")) // hash a string, NOT a file
                .arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
        )
    }
}

// ── otool (macOS binary inspection) ──

pub(super) struct OtoolParser;
impl CommandParser for OtoolParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        parse_with(
            base_cmd("otool")
                .arg(bool_s('L')) // shared libraries
                .arg(bool_s('l')) // load commands
                .arg(bool_s('h')) // Mach header
                .arg(bool_s('t')) // text section
                .arg(bool_s('d')) // data section
                .arg(bool_s('o')) // Objective-C segment
                .arg(bool_s('r')) // relocation entries
                .arg(bool_s('I')) // indirect symbol table
                .arg(bool_s('S')) // stab symbols
                .arg(bool_s('v')) // verbose
                .arg(bool_s('V')) // very verbose
                .arg(bool_s('X')) // omit leading addresses
                .arg(bool_s('f')) // fat headers
                .arg(val_s('p')) // start at symbol name
                .arg(val_l("arch"))
                .arg(files_arg()),
            args,
            cwd,
            extract_positional_reads,
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
            args,
            cwd,
            extract_positional_reads,
        )
    }
}
