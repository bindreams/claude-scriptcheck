use super::writers::*;
use super::CommandParser;
use crate::file_access::AccessScope;
use pretty_assertions::assert_eq;

fn sub(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Subtree(s.to_string()))
        .collect()
}

fn writes(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn rm_basic() {
    let r = RmParser.parse(&["-rf", "/tmp/foo"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert_eq!(r.writes, sub(&["/tmp/foo"]));
}

#[skuld::test]
fn rm_double_dash() {
    let r = RmParser.parse(&["--", "-weird-file"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/-weird-file"]));
}

// ── tee ──

#[skuld::test]
fn tee_writes_files() {
    let r = TeeParser.parse(&["-a", "out.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

// ── grep ──

#[skuld::test]
fn truncate_writes_files() {
    let r = TruncateParser
        .parse(&["-s", "0", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn truncate_size_not_file() {
    let r = TruncateParser
        .parse(&["--size", "1M", "a.bin", "b.bin"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/a.bin", "/tmp/b.bin"]));
}

// ── jq ──

#[skuld::test]
fn rm_bsd_overwrite_flag() {
    // macOS rm -P (overwrite before deleting)
    let r = RmParser.parse(&["-Prf", "/tmp/sensitive"], "/tmp").unwrap();
    assert_eq!(r.writes, sub(&["/tmp/sensitive"]));
}

// Recursion scopes ================================================================================

#[skuld::test]
fn rm_recursive_operands_are_subtree() {
    let r = RmParser.parse(&["-rf", "/tmp/dir"], "/tmp").unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir"]));
}

#[skuld::test]
fn rm_capital_r_operands_are_subtree() {
    let r = RmParser.parse(&["-R", "/tmp/dir"], "/tmp").unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir"]));
}

#[skuld::test]
fn rm_without_r_operands_are_exact() {
    let r = RmParser.parse(&["-f", "/tmp/file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}
