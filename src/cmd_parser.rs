mod helpers;
mod readers;
mod writers;
mod grep;
mod filesystem;
mod compression;
mod network;
mod archive;
mod find;
mod sed;
mod tar;
mod dd;
mod script_runners;

use crate::file_access;

/// Resolved file paths a command will access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFileAccesses {
    /// Absolute paths the command reads from.
    pub reads: Vec<String>,
    /// Absolute paths the command writes to.
    pub writes: Vec<String>,
    /// If the command takes an inline script (e.g. `-c '...'` or `-e '...'`),
    /// the 0-based index into the parser's args slice (excluding the command
    /// name) where the script text begins.  Used by the checker to truncate
    /// the logged rule to `Bash(cmd -c *)` instead of including the literal
    /// script text.
    pub inline_script_start: Option<usize>,
}

impl CommandFileAccesses {
    pub fn empty() -> Self {
        Self {
            reads: Vec::new(),
            writes: Vec::new(),
            inline_script_start: None,
        }
    }

    pub fn filter_sentinel(mut self, sentinel: &str) -> Self {
        self.reads.retain(|p| !p.contains(sentinel));
        self.writes.retain(|p| !p.contains(sentinel));
        self // inline_script_start is preserved as-is
    }
}

/// Trait that each known-command parser implements.
pub trait CommandParser: Send + Sync {
    /// Parse the command's arguments and return file accesses.
    /// `args` are the arguments *after* the command name (already concrete strings).
    /// `cwd` is the working directory, used to resolve relative paths.
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String>;
}

/// Result of parsing a command's arguments.
pub enum CmdParseResult {
    /// Successful parse — file accesses extracted (may be empty).
    Parsed(CommandFileAccesses),
    /// Parser rejected the arguments — caller should ask the user and log the error.
    ParseFailed { cmd_name: String, message: String },
}

pub const SENTINEL: &str = "__CLAUDE_DYNAMIC__";

/// Main entry point: parse a known command's arguments into file accesses.
///
/// `cmd_name` — the command name (e.g. "grep").
/// `args` — arguments after the command name. `None` = dynamic/unresolvable.
/// `cwd` — working directory for resolving relative paths.
pub fn parse_file_accesses(
    cmd_name: &str,
    args: &[Option<String>],
    cwd: &str,
) -> CmdParseResult {
    let parser = match get_parser(cmd_name) {
        Some(p) => p,
        None => return CmdParseResult::Parsed(CommandFileAccesses::empty()),
    };

    // Substitute None → sentinel so positional ordering is preserved for the parser.
    let concrete: Vec<String> = args
        .iter()
        .map(|a| a.clone().unwrap_or_else(|| SENTINEL.to_string()))
        .collect();
    let str_args: Vec<&str> = concrete.iter().map(|s| s.as_str()).collect();

    match parser.parse(&str_args, cwd) {
        Ok(accesses) => CmdParseResult::Parsed(accesses.filter_sentinel(SENTINEL)),
        Err(msg) => CmdParseResult::ParseFailed {
            cmd_name: cmd_name.to_string(),
            message: msg,
        },
    }
}

/// Look up the parser for a known command.
/// Returns `None` for unknown commands and commands with no file access.
pub fn get_parser(cmd_name: &str) -> Option<&'static dyn CommandParser> {
    use readers::*;
    use writers::*;
    use grep::*;
    use filesystem::*;
    use compression::*;
    use network::*;
    use archive::*;
    use find::*;
    use sed::*;
    use tar::*;
    use dd::*;
    use script_runners::*;

    match cmd_name {
        // Simple readers
        "cat" => Some(&CatParser),
        "head" => Some(&HeadParser),
        "tail" => Some(&TailParser),
        "less" => Some(&LessParser),
        "more" => Some(&MoreParser),
        "wc" => Some(&WcParser),
        "file" => Some(&FileParser),
        "stat" => Some(&StatParser),
        "md5sum" => Some(&Md5sumParser),
        "shasum" => Some(&ShasumParser),
        "sha256sum" => Some(&Sha256sumParser),
        "xxd" => Some(&XxdParser),
        "hexdump" => Some(&HexdumpParser),
        "strings" => Some(&StringsParser),
        "readelf" => Some(&ReadelfParser),
        "objdump" => Some(&ObjdumpParser),
        "nm" => Some(&NmParser),
        "ldd" => Some(&LddParser),
        "size" => Some(&SizeParser),
        "cut" => Some(&CutParser),
        "tac" => Some(&TacParser),
        "nl" => Some(&NlParser),
        "paste" => Some(&PasteParser),
        "rev" => Some(&RevParser),
        "expand" => Some(&ExpandParser),
        "unexpand" => Some(&UnexpandParser),
        "fold" => Some(&FoldParser),
        "column" => Some(&ColumnParser),
        "od" => Some(&OdParser),
        "zcat" => Some(&ZcatParser),
        "bzcat" => Some(&BzcatParser),
        "xzcat" => Some(&XzcatParser),
        "readlink" => Some(&ReadlinkParser),
        "du" => Some(&DuParser),
        "lsof" => Some(&LsofParser),
        "base64" => Some(&Base64Parser),
        "sha1sum" => Some(&Sha1sumParser),
        "sha512sum" => Some(&Sha512sumParser),
        "sha224sum" => Some(&Sha224sumParser),
        "sha384sum" => Some(&Sha384sumParser),
        "b2sum" => Some(&B2sumParser),
        "cksum" => Some(&CksumParser),
        "sum" => Some(&SumParser),
        "md5" => Some(&Md5Parser),
        "otool" => Some(&OtoolParser),

        // Simple writers
        "rm" => Some(&RmParser),
        "rmdir" => Some(&RmdirParser),
        "tee" => Some(&TeeParser),
        "truncate" => Some(&TruncateParser),

        // Pattern-then-files readers
        "grep" => Some(&GrepParser),
        "rg" => Some(&RgParser),
        "awk" => Some(&AwkParser),
        "jq" => Some(&JqParser),

        // Compression commands
        "gzip" => Some(&GzipParser),
        "gunzip" => Some(&GunzipParser),
        "bzip2" => Some(&Bzip2Parser),
        "bunzip2" => Some(&Bunzip2Parser),
        "xz" => Some(&XzParser),
        "unxz" => Some(&UnxzParser),

        // Network download
        "curl" => Some(&CurlParser),
        "wget" => Some(&WgetParser),

        // Archive commands
        "zip" => Some(&ZipParser),
        "unzip" => Some(&UnzipParser),
        "patch" => Some(&PatchParser),
        "split" => Some(&SplitParser),
        "csplit" => Some(&CsplitParser),

        // Commands with special semantics
        "cp" => Some(&CpParser),
        "mv" => Some(&MvParser),
        "install" => Some(&InstallParser),
        "ln" => Some(&LnParser),
        "mkdir" => Some(&MkdirParser),
        "touch" => Some(&TouchParser),
        "diff" => Some(&DiffParser),
        "sort" => Some(&SortParser),
        "uniq" => Some(&UniqParser),
        "chmod" => Some(&ChmodParser),
        "chown" => Some(&ChownParser),
        "chgrp" => Some(&ChgrpParser),
        "source" | "." => Some(&SourceParser),

        // Manual parsers (non-standard syntax)
        "find" => Some(&FindParser),
        "sed" => Some(&SedParser),
        "tar" => Some(&TarParser),
        "dd" => Some(&DdParser),

        // Script runners — detect inline scripts and script-file reads
        "bash" | "sh" | "zsh" | "dash" => Some(&ShellParser),
        "python" | "python3" => Some(&PythonParser),
        "ruby" => Some(&RubyParser),
        "node" | "nodejs" => Some(&NodeParser),
        "perl" => Some(&PerlParser),

        // Commands that don't touch files — return None (no parser needed).
        "tr" | "echo" | "printf" | "pwd" | "whoami" | "hostname" | "uname" | "date"
        | "uptime" | "env" | "printenv" | "id" | "groups" | "true" | "false" | "test"
        | "[" | "which" | "whereis" | "type" | "basename" | "dirname" | "realpath" | "expr"
        | "seq" | "sleep" | "wait" | "exit" | "return" | "break" | "continue" | "shift"
        | "set" | "unset" | "export" | "alias" | "unalias" | "declare" | "local"
        | "readonly" | "typeset" | "let" | "read" | "cd" | "pushd" | "popd" | "dirs"
        | "hash" | "command" | "builtin" | "exec" | "times" | "trap" | "kill" | "jobs"
        | "fg" | "bg" | "disown" | "suspend" | "logout" | "history" | "fc" | "bind"
        | "complete" | "compgen" | "compopt" | "mapfile" | "readarray" | "getopts"
        | "shopt" | "enable" | "help" | "caller" | "ulimit" | "umask"
        // Process/network/terminal/system commands with no file access
        | "yes" | "tput" | "stty" | "ping" | "nc" | "dig" | "host" | "nslookup"
        | "ps" | "pgrep" | "pkill" | "df" | "free" | "mktemp"
        | "pbcopy" | "pbpaste" | "uuidgen" => None,

        _ => None,
    }
}

/// Resolve a path relative to cwd. Re-exports from file_access for use by parsers.
pub fn resolve(path: &str, cwd: &str) -> String {
    file_access::resolve_path(path, cwd)
}

mod helpers_tests;
mod readers_tests;
mod writers_tests;
mod grep_tests;
mod filesystem_tests;
mod compression_tests;
mod network_tests;
mod archive_tests;
mod find_tests;
mod sed_tests;
mod tar_tests;
mod dd_tests;
mod script_runners_tests;
