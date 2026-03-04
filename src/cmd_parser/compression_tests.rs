use super::compression::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn reads(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn writes(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn gzip_default_writes() {
    let r = GzipParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn gzip_stdout_reads() {
    let r = GzipParser.parse(&["-c", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn gzip_suffix_not_file() {
    let r = GzipParser.parse(&["-S", ".z", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn gunzip_default_writes() {
    let r = GunzipParser.parse(&["file.gz"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.gz"]));
}

#[skuld::test]
fn bzip2_stdout_reads() {
    let r = Bzip2Parser.parse(&["-c", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn bunzip2_default_writes() {
    let r = Bunzip2Parser.parse(&["file.bz2"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.bz2"]));
}

#[skuld::test]
fn xz_default_writes() {
    let r = XzParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn xz_stdout_reads() {
    let r = XzParser.parse(&["--stdout", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[skuld::test]
fn unxz_default_writes() {
    let r = UnxzParser.parse(&["file.xz"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.xz"]));
}

// ── curl / wget ──

#[skuld::test]
fn gzip_numeric_level() {
    // Both GNU and BSD support -1 through -9
    let r = GzipParser.parse(&["-9", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn gzip_best_fast() {
    // GNU gzip --best / --fast
    let r = GzipParser.parse(&["--best", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn xz_threads_flag() {
    // GNU xz -T (threads) — value not file
    let r = XzParser.parse(&["-T", "4", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// ── chmod/chown with BSD flags ──
