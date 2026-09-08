use super::grep::*;
use super::CommandParser;
use crate::file_access::AccessScope;
use pretty_assertions::assert_eq;

fn sub(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Subtree(s.to_string()))
        .collect()
}

#[allow(dead_code)]
fn unbounded(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::UnboundedSubtree(s.to_string()))
        .collect()
}

fn reads(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn grep_pattern_then_file() {
    let r = GrepParser.parse(&["TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_e_flag_consumes_pattern() {
    let r = GrepParser
        .parse(&["-e", "TODO", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_multiple_e_flags() {
    let r = GrepParser
        .parse(&["-e", "TODO", "-e", "FIXME", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_f_flag_is_read() {
    let r = GrepParser
        .parse(&["-f", "patterns.txt", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/patterns.txt", "/tmp/file.txt"]));
}

#[skuld::test]
fn grep_pattern_only_no_files() {
    let r = GrepParser.parse(&["pattern"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[skuld::test]
fn grep_with_value_flags() {
    let r = GrepParser
        .parse(&["-m", "10", "-A", "3", "pattern", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_recursive_with_dir() {
    let r = GrepParser
        .parse(&["-r", "TODO", "/tmp/src"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src"]));
}

// ── rg ──

#[skuld::test]
fn rg_pattern_then_file(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("file.txt"), "x").unwrap();
    let r = RgParser.parse(&["TODO", "file.txt"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/file.txt")]));
}

#[skuld::test]
fn rg_e_flag_consumes_pattern(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("file.txt"), "x").unwrap();
    let r = RgParser.parse(&["-e", "TODO", "file.txt"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/file.txt")]));
}

// ── awk ──

#[skuld::test]
fn awk_program_then_file() {
    let r = AwkParser
        .parse(&["/pattern/{ print }", "data.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

#[skuld::test]
fn awk_program_only() {
    let r = AwkParser.parse(&["/pattern/{ print }"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[skuld::test]
fn awk_f_flag_is_read() {
    let r = AwkParser
        .parse(&["-f", "script.awk", "data.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.awk", "/tmp/data.txt"]));
}

#[skuld::test]
#[allow(non_snake_case)]
fn awk_F_value_not_treated_as_file() {
    let r = AwkParser
        .parse(&["-F", ",", "{ print $1 }", "data.csv"], "/tmp")
        .unwrap();
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
    let r = JqParser
        .parse(&["--slurpfile", "x", "data.json", "."], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.json"]));
}

#[skuld::test]
fn jq_from_file_makes_all_positionals_data() {
    let r = JqParser
        .parse(&["--from-file", "prog.jq", "a.json", "b.json"], "/tmp")
        .unwrap();
    assert_eq!(
        r.reads,
        reads(&["/tmp/prog.jq", "/tmp/a.json", "/tmp/b.json"])
    );
}

// ── compression ──

#[skuld::test]
fn grep_gnu_include_flag() {
    // GNU grep --include (not on all BSD variants)
    let r = GrepParser
        .parse(&["-r", "--include", "*.rs", "TODO", "src/"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src/"]));
}

#[skuld::test]
fn grep_gnu_exclude_dir() {
    // GNU grep --exclude-dir
    let r = GrepParser
        .parse(&["-r", "--exclude-dir", ".git", "TODO", "src/"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src/"]));
}

#[skuld::test]
fn grep_bsd_null_flag() {
    // Both GNU and BSD support -Z/--null
    let r = GrepParser
        .parse(&["-rlZ", "pattern", "dir/"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/dir/"]));
}

// ── sort GNU-only flags ──

// Recursion scopes ================================================================================

#[skuld::test]
fn grep_recursive_flag_makes_operand_subtree() {
    let r = GrepParser
        .parse(&["-r", "TODO", "/tmp/src"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src"]));
}

#[skuld::test]
fn grep_capital_r_is_following() {
    let r = GrepParser
        .parse(&["-R", "TODO", "/tmp/src"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, unbounded(&["/tmp/src"]));
}

#[skuld::test]
fn grep_without_recursive_flag_stays_exact() {
    let r = GrepParser
        .parse(&["TODO", "/tmp/file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn grep_directories_recurse_value_makes_operand_subtree() {
    let r = GrepParser
        .parse(&["-d", "recurse", "TODO", "/tmp/src"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src"]));
}

#[skuld::test]
fn grep_recursive_with_no_operand_reads_cwd() {
    let r = GrepParser.parse(&["-r", "TODO"], "/tmp/proj").unwrap();
    assert_eq!(r.reads, sub(&["/tmp/proj"]));
}

#[skuld::test]
fn grep_pattern_file_stays_exact_under_recursion() {
    let r = GrepParser
        .parse(&["-r", "-f", "pats.txt", "/tmp/src"], "/tmp")
        .unwrap();
    assert_eq!(
        r.reads,
        vec![
            AccessScope::Exact("/tmp/pats.txt".into()),
            AccessScope::Subtree("/tmp/src".into()),
        ],
    );
}

#[skuld::test]
fn rg_directory_operand_is_subtree(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("sub")).unwrap();
    let r = RgParser.parse(&["TODO", "sub"], &cwd).unwrap();
    assert_eq!(r.reads, sub(&[&format!("{cwd}/sub")]));
}

#[skuld::test]
fn rg_file_operand_is_exact(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    let r = RgParser.parse(&["TODO", "f.txt"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/f.txt")]));
}

#[skuld::test]
fn rg_missing_operand_is_subtree(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    let r = RgParser.parse(&["TODO", "nope"], &cwd).unwrap();
    assert_eq!(r.reads, sub(&[&format!("{cwd}/nope")]));
}

#[skuld::test]
fn rg_no_path_reads_cwd() {
    let r = RgParser.parse(&["TODO"], "/tmp/proj").unwrap();
    assert_eq!(r.reads, sub(&["/tmp/proj"]));
}

#[skuld::test]
fn rg_follow_is_unbounded(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("sub")).unwrap();
    let r = RgParser.parse(&["--follow", "TODO", "sub"], &cwd).unwrap();
    assert_eq!(r.reads, unbounded(&[&format!("{cwd}/sub")]));
}
