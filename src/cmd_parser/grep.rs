use clap::{ArgAction, ArgMatches};

use super::helpers::*;
use super::{resolve, CommandFileAccesses, CommandParser};

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
        file_only: None,
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
            file_only: None,
        })
    }
}

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
            .arg(
                clap::Arg::new("arg".to_string())
                    .long("arg".to_string())
                    .num_args(2)
                    .action(ArgAction::Append)
                    .required(false),
            )
            .arg(
                clap::Arg::new("argjson".to_string())
                    .long("argjson".to_string())
                    .num_args(2)
                    .action(ArgAction::Append)
                    .required(false),
            )
            .arg(
                clap::Arg::new("slurpfile".to_string())
                    .long("slurpfile".to_string())
                    .num_args(2)
                    .action(ArgAction::Append)
                    .required(false),
            )
            .arg(
                clap::Arg::new("rawfile".to_string())
                    .long("rawfile".to_string())
                    .num_args(2)
                    .action(ArgAction::Append)
                    .required(false),
            )
            .arg(val_l("from-file"))
            .arg(val('L', "library-path"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();

        // --slurpfile NAME FILE and --rawfile NAME FILE → FILE (2nd value) is a read
        for flag_name in &["slurpfile", "rawfile"] {
            if let Some(vals) = matches.get_many::<String>(flag_name) {
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
            file_only: None,
        })
    }
}
