use super::writers::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn writes(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn rm_basic() {
    let r = RmParser.parse(&["-rf", "/tmp/foo"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert_eq!(r.writes, writes(&["/tmp/foo"]));
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
    assert_eq!(r.writes, writes(&["/tmp/sensitive"]));
}
