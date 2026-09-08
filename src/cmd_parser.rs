mod archive;
mod compression;
mod dd;
mod filesystem;
mod find;
pub(crate) mod git;
mod grep;
mod helpers;
mod ls;
mod network;
mod readers;
mod script_runners;
mod sed;
mod tar;
mod wrappers;
mod writers;

use crate::file_access::{self, AccessScope};

/// Resolved file paths a command will access.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandFileAccesses {
    /// Path sets the command reads from.
    pub reads: Vec<AccessScope>,
    /// Path sets the command writes to.
    pub writes: Vec<AccessScope>,
    /// If the command takes an inline script (e.g. `-c '...'` or `-e '...'`),
    /// the 0-based index into the parser's args slice (excluding the command
    /// name) where the script text begins.  Used by the checker to truncate
    /// the logged rule to `Bash(cmd -c *)` instead of including the literal
    /// script text.
    pub inline_script_start: Option<usize>,
    /// Parser-declared override for file-only status.
    /// - `Some(true)`: file accesses fully characterize the command's effects
    ///   (no `Bash()` rule needed when file accesses are present).
    /// - `Some(false)`: command has side effects beyond file I/O (e.g. network).
    /// - `None`: defer to `is_file_only_command()` lookup (default for all
    ///   existing parsers).
    pub file_only: Option<bool>,
    /// Normalized name of the "real" command when a wrapper (e.g. `uv run`)
    /// delegates to an inner command. The checker uses this to decide whether
    /// to invoke Python AST analysis and for `is_file_only_command()` checks.
    pub effective_cmd_name: Option<String>,
}

impl CommandFileAccesses {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace every access whose resolved path came from an unresolved
    /// argument with an [`AccessScope::Unresolved`] naming that argument.
    ///
    /// Ask, don't drop. Deleting the access — the behaviour this replaces —
    /// read "cannot resolve" as "no file access", so a command reached a path
    /// with no rule consulted.
    pub fn mark_unresolved(mut self, args: &[ResolvedArg]) -> Self {
        mark_scopes(&mut self.reads, args);
        mark_scopes(&mut self.writes, args);
        self // inline_script_start and effective_cmd_name preserved as-is
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

/// One command argument, as the checker resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedArg {
    /// A statically determined value.
    Static(String),
    /// A word whose value could not be determined, carrying
    /// [`crate::unresolved::describe_argument`]'s rendering of it.
    Unresolved(String),
}

impl ResolvedArg {
    /// The value, for a statically determined argument.
    pub fn as_static(&self) -> Option<&str> {
        match self {
            Self::Static(s) => Some(s),
            Self::Unresolved(_) => None,
        }
    }

    pub fn is_unresolved(&self) -> bool {
        matches!(self, Self::Unresolved(_))
    }
}

/// Placeholder standing in for the unresolved argument at `index` while a
/// parser runs, so the parser's positional logic is unaffected.
///
/// The index is what lets a resolved path be traced back to the argument that
/// produced it. The trailing `__` delimits, so `sentinel(1)` is not a substring
/// of `sentinel(11)`.
pub fn sentinel(index: usize) -> String {
    format!("__CLAUDE_DYNAMIC_{index}__")
}

/// The lowest unresolved-argument index whose sentinel appears in `scope`.
///
/// Provenance is carried as a string and recovered by substring search, so a
/// static path that literally contains a sentinel *and* sits alongside an
/// unresolved argument at that index is mis-attributed. Requiring
/// `is_unresolved` keeps the far more likely case — a sentinel-shaped path with
/// no unresolved argument anywhere — honest, and bounds the damage to the one
/// colliding access rather than the whole command. Structured provenance is the
/// real fix and is tracked separately.
fn sentinel_index(scope: &AccessScope, args: &[ResolvedArg]) -> Option<usize> {
    let path = scope.path();
    (0..args.len()).find(|i| args[*i].is_unresolved() && path.contains(&sentinel(*i)))
}

/// Replace each sentinel-bearing scope with the rendering of the argument that
/// produced it.
///
/// Any recursion classification the scope carried is discarded. Nothing is lost:
/// `Unresolved` already satisfies no allow rule, the strongest of the outcomes
/// `Subtree` and `UnboundedSubtree` produce.
fn mark_scopes(scopes: &mut [AccessScope], args: &[ResolvedArg]) {
    for scope in scopes {
        let Some(i) = sentinel_index(scope, args) else {
            continue;
        };
        if let Some(ResolvedArg::Unresolved(word)) = args.get(i) {
            *scope = AccessScope::Unresolved(word.clone());
        }
    }
}

/// Main entry point: parse a known command's arguments into file accesses.
///
/// `cmd_name` — the command name (e.g. "grep").
/// `args` — arguments after the command name; index `i` here is the `i` in
/// [`sentinel`].
/// `cwd` — working directory for resolving relative paths.
pub fn parse_file_accesses(cmd_name: &str, args: &[ResolvedArg], cwd: &str) -> CmdParseResult {
    let parser = match get_parser(normalize_cmd_name(cmd_name)) {
        Some(p) => p,
        None => return CmdParseResult::Parsed(CommandFileAccesses::empty()),
    };

    // Substitute a per-index sentinel for each unresolved argument, so the
    // parser sees an argument in every slot and its positional logic holds.
    let concrete: Vec<String> = args
        .iter()
        .enumerate()
        .map(|(i, a)| match a {
            ResolvedArg::Static(s) => s.clone(),
            ResolvedArg::Unresolved(_) => sentinel(i),
        })
        .collect();
    let str_args: Vec<&str> = concrete.iter().map(|s| s.as_str()).collect();

    match parser.parse(&str_args, cwd) {
        Ok(accesses) => CmdParseResult::Parsed(accesses.mark_unresolved(args)),
        Err(msg) => CmdParseResult::ParseFailed {
            cmd_name: cmd_name.to_string(),
            message: msg,
        },
    }
}

/// Look up the parser for a known command.
/// Returns `None` for unknown commands and commands with no file access.
pub fn get_parser(cmd_name: &str) -> Option<&'static dyn CommandParser> {
    use archive::*;
    use compression::*;
    use dd::*;
    use filesystem::*;
    use find::*;
    use git::*;
    use grep::*;
    use ls::*;
    use network::*;
    use readers::*;
    use script_runners::*;
    use sed::*;
    use tar::*;
    use wrappers::*;
    use writers::*;

    match cmd_name {
        // Compound commands
        "git" => Some(&GitParser),
        "uv" => Some(&UvParser),

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
        "ls" => Some(&LsParser),
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
        _ if is_python_cmd(cmd_name) => Some(&PythonParser),
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

/// Normalize a command name by extracting its basename and stripping any
/// Windows PATHEXT suffix (`.com .exe .bat .cmd .vbs .vbe .js .jse .wsf .wsh
/// .msc`, case-insensitive). Applied unconditionally on every OS so settings
/// files port across Windows / WSL / Unix without platform-specific rewrites.
///
/// `/usr/bin/python3` → `python3`, `C:\Python312\python.exe` → `python`,
/// `bash.exe` → `bash`, `./tools/rg.cmd` → `rg`, `cat` → `cat`.
pub fn normalize_cmd_name(name: &str) -> &str {
    // Extract basename (after last path separator)
    let basename = match name.rfind('/').or_else(|| name.rfind('\\')) {
        Some(i) => &name[i + 1..],
        None => name,
    };
    // Strip any PATHEXT suffix (case-insensitive)
    crate::path_util::strip_pathext_suffix(basename)
}

/// Returns true if `name` (already normalized) looks like a Python interpreter.
/// Matches `python`, `python3`, `python3.12`, `python3.13t`, etc.
pub fn is_python_cmd(name: &str) -> bool {
    name == "python" || name.starts_with("python3")
}

/// Resolve a path relative to cwd into an `Exact` access scope — the shape
/// almost every parser wants for an operand it names directly.
pub fn resolve(path: &str, cwd: &str) -> AccessScope {
    AccessScope::Exact(resolve_str(path, cwd))
}

/// How far below an operand a command reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recursion {
    /// The operand itself and nothing else.
    No,
    /// The operand and everything beneath it.
    Yes,
    /// Recursive only when the operand is a directory (`rg pat x`, `tar cf a.tar x`).
    IfDir,
    /// Recursive with symlinks followed, so the walk can leave the subtree.
    Following,
}

/// Resolve an operand into the scope the command will actually touch.
pub fn resolve_scoped(path: &str, cwd: &str, recursion: Recursion) -> AccessScope {
    let resolved = resolve_str(path, cwd);
    match recursion {
        Recursion::No => AccessScope::Exact(resolved),
        Recursion::Yes => AccessScope::Subtree(resolved),
        Recursion::Following => AccessScope::UnboundedSubtree(resolved),
        // The stat is a check-time snapshot and the command runs afterwards, so
        // an operand swapped from file to directory inside that window is
        // classified `Exact` and its subtree goes unchecked. That race is
        // accepted deliberately: scriptcheck defends against accidents, not
        // malice — an agent that has genuinely gone rogue circumvents the hook
        // entirely — and the precision is worth more than closing it. This is a
        // recorded exception to the project's "never rely on data races" rule,
        // not an oversight; do not delete the narrowing to "fix" it.
        Recursion::IfDir => match std::fs::metadata(&resolved) {
            Ok(meta) if !meta.is_dir() => AccessScope::Exact(resolved),
            // A directory, or a path that cannot be stat'd at all: assume the
            // walk happens.
            _ => AccessScope::Subtree(resolved),
        },
    }
}

/// Resolve a path relative to cwd as a plain string, for parsers that do path
/// arithmetic on the result (e.g. git's `--git-dir` / `--work-tree` handling)
/// rather than recording it as an access.
pub fn resolve_str(path: &str, cwd: &str) -> String {
    file_access::resolve_path(path, cwd)
}

mod archive_tests;
mod compression_tests;
mod dd_tests;
mod filesystem_tests;
mod find_tests;
mod git_tests;
mod grep_tests;
mod helpers_tests;
mod ls_tests;
mod network_tests;
mod readers_tests;
mod script_runners_tests;
mod sed_tests;
mod tar_tests;
mod wrappers_tests;
mod writers_tests;

#[cfg(test)]
mod tests {
    use super::*;

    // normalize_cmd_name tests ========================================================================================

    #[test]
    fn normalize_bare_name() {
        assert_eq!(normalize_cmd_name("python"), "python");
    }

    #[test]
    fn normalize_exe_suffix() {
        assert_eq!(normalize_cmd_name("python.exe"), "python");
    }

    #[test]
    fn normalize_unix_absolute_path() {
        assert_eq!(normalize_cmd_name("/usr/bin/python3"), "python3");
    }

    #[test]
    fn normalize_windows_absolute_path() {
        assert_eq!(normalize_cmd_name("C:\\Python312\\python.exe"), "python");
    }

    #[test]
    fn normalize_forward_slash_path() {
        assert_eq!(normalize_cmd_name("C:/Python312/python.exe"), "python");
    }

    #[test]
    fn normalize_venv_path() {
        assert_eq!(normalize_cmd_name(".venv/Scripts/python.exe"), "python");
    }

    #[test]
    fn normalize_versioned_python() {
        assert_eq!(normalize_cmd_name("python3.12"), "python3.12");
    }

    #[test]
    fn normalize_bash_exe() {
        assert_eq!(normalize_cmd_name("bash.exe"), "bash");
    }

    #[test]
    fn normalize_just_exe() {
        assert_eq!(normalize_cmd_name(".exe"), "");
    }

    #[test]
    fn normalize_cmd_suffix() {
        assert_eq!(normalize_cmd_name("foo.cmd"), "foo");
    }

    #[test]
    fn normalize_bat_suffix() {
        assert_eq!(normalize_cmd_name("foo.bat"), "foo");
    }

    #[test]
    fn normalize_com_suffix() {
        assert_eq!(normalize_cmd_name("foo.com"), "foo");
    }

    #[test]
    fn normalize_vbs_suffix() {
        assert_eq!(normalize_cmd_name("foo.vbs"), "foo");
    }

    #[test]
    fn normalize_js_suffix_case_insensitive() {
        assert_eq!(normalize_cmd_name("foo.JS"), "foo");
    }

    #[test]
    fn normalize_no_strip_for_unknown_suffix() {
        assert_eq!(normalize_cmd_name("foo.py"), "foo.py");
    }

    #[test]
    fn normalize_windows_path_with_cmd_suffix() {
        assert_eq!(normalize_cmd_name("C:\\tools\\foo.cmd"), "foo");
    }

    #[test]
    fn normalize_relative_path_with_cmd_suffix() {
        assert_eq!(normalize_cmd_name("./tools/rg.cmd"), "rg");
    }

    // is_python_cmd tests =============================================================================================

    #[test]
    fn is_python_cmd_bare() {
        assert!(is_python_cmd("python"));
    }

    #[test]
    fn is_python_cmd_python3() {
        assert!(is_python_cmd("python3"));
    }

    #[test]
    fn is_python_cmd_versioned() {
        assert!(is_python_cmd("python3.12"));
    }

    #[test]
    fn is_python_cmd_free_threaded() {
        assert!(is_python_cmd("python3.13t"));
    }

    #[test]
    fn is_python_cmd_not_ruby() {
        assert!(!is_python_cmd("ruby"));
    }

    #[test]
    fn is_python_cmd_not_python2() {
        assert!(!is_python_cmd("python2"));
    }
}
