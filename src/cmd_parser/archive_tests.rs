use super::archive::*;
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

fn writes(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn zip_creates_archive() {
    let r = ZipParser
        .parse(&["archive.zip", "a.txt", "b.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.zip"]));
}

#[skuld::test]
fn zip_recursive() {
    let r = ZipParser
        .parse(&["-r", "archive.zip", "dir/"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, sub(&["/tmp/dir/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.zip"]));
}

#[skuld::test]
fn unzip_extracts() {
    let r = UnzipParser
        .parse(&["archive.zip", "-d", "/dest"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.zip"]));
    assert_eq!(r.writes, sub(&["/dest"]));
}

#[skuld::test]
fn unzip_no_dest() {
    // Extraction without -d unpacks into the working directory.
    let r = UnzipParser.parse(&["archive.zip"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.zip"]));
    assert_eq!(r.writes, sub(&["/tmp"]));
}

// ── patch ──

#[skuld::test]
fn patch_input_and_original() {
    let r = PatchParser
        .parse(&["-i", "fix.patch", "file.c"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/fix.patch"]));
    assert_eq!(r.writes, writes(&["/tmp/file.c"]));
}

#[skuld::test]
fn patch_output_flag() {
    let r = PatchParser
        .parse(&["-i", "fix.patch", "-o", "new.c"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/fix.patch"]));
    assert_eq!(r.writes, writes(&["/tmp/new.c"]));
}

#[skuld::test]
fn patch_two_positionals() {
    let r = PatchParser.parse(&["file.c", "fix.patch"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/fix.patch"]));
    assert_eq!(r.writes, writes(&["/tmp/file.c"]));
}

// ── split / csplit ──

#[skuld::test]
fn split_reads_input() {
    let r = SplitParser
        .parse(&["-b", "1M", "bigfile.bin"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/bigfile.bin"]));
}

#[skuld::test]
fn split_with_prefix() {
    let r = SplitParser
        .parse(&["bigfile.bin", "chunk_"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/bigfile.bin"]));
}

#[skuld::test]
fn csplit_reads_input() {
    let r = CsplitParser
        .parse(&["file.txt", "/pattern/"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ══════════════════════════════════════════════════════════════════════
// SELinux variant tests
// ══════════════════════════════════════════════════════════════════════

// Recursion scopes ====================================================================================================

#[skuld::test]
fn zip_recurse_paths_sources_are_subtree() {
    let r = ZipParser.parse(&["-r", "a.zip", "dir"], "/tmp").unwrap();
    assert_eq!(r.reads, sub(&["/tmp/dir"]));
    assert_eq!(r.writes, writes(&["/tmp/a.zip"]));
}

#[skuld::test]
fn zip_without_r_sources_are_exact() {
    let r = ZipParser.parse(&["a.zip", "f.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/f.txt"]));
}

#[skuld::test]
fn unzip_destination_directory_is_subtree() {
    let r = UnzipParser.parse(&["a.zip", "-d", "out"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.zip"]));
    assert_eq!(r.writes, sub(&["/tmp/out"]));
}

#[skuld::test]
fn unzip_without_d_writes_cwd() {
    let r = UnzipParser.parse(&["a.zip"], "/tmp/proj").unwrap();
    assert_eq!(r.writes, sub(&["/tmp/proj"]));
}
