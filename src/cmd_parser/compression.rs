use clap::ArgMatches;

use super::helpers::*;
use super::CommandFileAccesses;
use super::CommandParser;

// ─── Compression commands ────────────────────────────────────────────────────

/// Shared extraction for gzip/bzip2/xz family:
/// With -c/--stdout/--to-stdout → reads (output to stdout).
/// Without → writes (in-place modification).
fn parse_compression(matches: &ArgMatches, cwd: &str) -> CommandFileAccesses {
    let to_stdout = matches.get_count("stdout") > 0;

    let paths: Vec<String> = matches
        .get_many::<String>("files")
        .map(|vals| vals.map(|f| super::resolve(f, cwd)).collect())
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
