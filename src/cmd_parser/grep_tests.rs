use super::grep::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn reads(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn grep_pattern_then_file() {
    let r = GrepParser.parse(&["TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_e_flag_consumes_pattern() {
    let r = GrepParser.parse(&["-e", "TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_multiple_e_flags() {
    let r = GrepParser.parse(&["-e", "TODO", "-e", "FIXME", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_f_flag_is_read() {
    let r = GrepParser.parse(&["-f", "patterns.txt", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/patterns.txt", "/tmp/file.txt"]));
}

#[skuld::test]
fn grep_pattern_only_no_files() {
    let r = GrepParser.parse(&["pattern"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[skuld::test]
fn grep_with_value_flags() {
    let r = GrepParser.parse(&["-m", "10", "-A", "3", "pattern", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_recursive_with_dir() {
    let r = GrepParser.parse(&["-r", "TODO", "/tmp/src"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
}

// ── rg ──

#[skuld::test]
fn rg_pattern_then_file() {
    let r = RgParser.parse(&["TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn rg_e_flag_consumes_pattern() {
    let r = RgParser.parse(&["-e", "TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── awk ──

#[skuld::test]
fn awk_program_then_file() {
    let r = AwkParser.parse(&["/pattern/{ print }", "data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

#[skuld::test]
fn awk_program_only() {
    let r = AwkParser.parse(&["/pattern/{ print }"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[skuld::test]
fn awk_f_flag_is_read() {
    let r = AwkParser.parse(&["-f", "script.awk", "data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.awk", "/tmp/data.txt"]));
}

#[skuld::test]
#[allow(non_snake_case)]
fn awk_F_value_not_treated_as_file() {
    let r = AwkParser.parse(&["-F", ",", "{ print $1 }", "data.csv"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.csv"]));
}

// ── cp ──

#[skuld::test]
fn jq_filter_then_files() {
    let r = JqParser.parse(&[".name", "data.json"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.json"]));
}

#[skuld::test]
fn jq_filter_only() {
    let r = JqParser.parse(&["."], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[skuld::test]
fn jq_slurpfile_is_read() {
    let r = JqParser.parse(&["--slurpfile", "x", "data.json", "."], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.json"]));
}

#[skuld::test]
fn jq_from_file_makes_all_positionals_data() {
    let r = JqParser.parse(&["--from-file", "prog.jq", "a.json", "b.json"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/prog.jq", "/tmp/a.json", "/tmp/b.json"]));
}

// ── compression ──

#[skuld::test]
fn grep_gnu_include_flag() {
    // GNU grep --include (not on all BSD variants)
    let r = GrepParser.parse(&["-r", "--include", "*.rs", "TODO", "src/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
}

#[skuld::test]
fn grep_gnu_exclude_dir() {
    // GNU grep --exclude-dir
    let r = GrepParser.parse(&["-r", "--exclude-dir", ".git", "TODO", "src/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
}

#[skuld::test]
fn grep_bsd_null_flag() {
    // Both GNU and BSD support -Z/--null
    let r = GrepParser.parse(&["-rlZ", "pattern", "dir/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
}

// ── sort GNU-only flags ──
