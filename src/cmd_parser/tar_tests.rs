use super::tar::*;
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

fn r(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

fn w(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn tar_create_mode(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("dir")).unwrap();
    let result = TarParser
        .parse(&["-cf", "archive.tar", "dir/"], &cwd)
        .unwrap();
    assert_eq!(result.reads, sub(&[&format!("{cwd}/dir/")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/archive.tar")]));
}

#[skuld::test]
fn tar_extract_mode() {
    // Extraction without -C unpacks into the working directory.
    let result = TarParser.parse(&["-xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    assert_eq!(result.writes, sub(&["/tmp"]));
}

#[skuld::test]
fn tar_extract_to_dir() {
    let result = TarParser
        .parse(&["-xf", "a.tar", "-C", "/dest"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/a.tar"]));
    assert_eq!(result.writes, sub(&["/dest"]));
}

#[skuld::test]
fn tar_legacy_syntax() {
    let result = TarParser.parse(&["xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_legacy_create(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let result = TarParser
        .parse(&["czf", "archive.tar.gz", "src/"], &cwd)
        .unwrap();
    assert_eq!(result.reads, sub(&[&format!("{cwd}/src/")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/archive.tar.gz")]));
}

#[skuld::test]
fn tar_list_mode() {
    let result = TarParser.parse(&["-tf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_long_flags(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    let result = TarParser
        .parse(
            &[
                "--create",
                "--file",
                "archive.tar",
                "--directory",
                "/src",
                ".",
            ],
            &cwd,
        )
        .unwrap();
    // `.` is the working directory, so tar recurses into it.
    assert_eq!(result.reads, sub(&[&format!("{cwd}/.")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/archive.tar")]));
}

#[skuld::test]
fn tar_long_flag_equals() {
    let result = TarParser
        .parse(&["--extract", "--file=archive.tar"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

// Recursion scopes ================================================================================

#[skuld::test]
fn tar_create_directory_source_is_subtree(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let result = TarParser.parse(&["cf", "a.tar", "src"], &cwd).unwrap();
    assert_eq!(result.reads, sub(&[&format!("{cwd}/src")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/a.tar")]));
}

#[skuld::test]
fn tar_create_file_source_is_exact(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    let result = TarParser.parse(&["cf", "a.tar", "f.txt"], &cwd).unwrap();
    assert_eq!(result.reads, r(&[&format!("{cwd}/f.txt")]));
}

#[skuld::test]
fn tar_dereference_is_following(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let result = TarParser
        .parse(&["-c", "-h", "-f", "a.tar", "src"], &cwd)
        .unwrap();
    assert_eq!(result.reads, unbounded(&[&format!("{cwd}/src")]));
}

#[skuld::test]
fn tar_extract_change_dir_is_subtree() {
    let result = TarParser
        .parse(&["xf", "/tmp/a.tar", "-C", "/dest"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/a.tar"]));
    assert_eq!(result.writes, sub(&["/dest"]));
}

#[skuld::test]
fn tar_extract_without_c_writes_cwd() {
    let result = TarParser.parse(&["xf", "/tmp/a.tar"], "/tmp/proj").unwrap();
    assert_eq!(result.writes, sub(&["/tmp/proj"]));
}
