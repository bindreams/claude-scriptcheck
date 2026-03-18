use super::tar::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn w(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn tar_create_mode() {
    let result = TarParser
        .parse(&["-cf", "archive.tar", "dir/"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/dir/"]));
    assert_eq!(result.writes, w(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_extract_mode() {
    let result = TarParser.parse(&["-xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn tar_extract_to_dir() {
    let result = TarParser
        .parse(&["-xf", "a.tar", "-C", "/dest"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/a.tar"]));
    assert_eq!(result.writes, w(&["/dest"]));
}

#[skuld::test]
fn tar_legacy_syntax() {
    let result = TarParser.parse(&["xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_legacy_create() {
    let result = TarParser
        .parse(&["czf", "archive.tar.gz", "src/"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/src/"]));
    assert_eq!(result.writes, w(&["/tmp/archive.tar.gz"]));
}

#[skuld::test]
fn tar_list_mode() {
    let result = TarParser.parse(&["-tf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_long_flags() {
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
            "/tmp",
        )
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/."]));
    assert_eq!(result.writes, w(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_long_flag_equals() {
    let result = TarParser
        .parse(&["--extract", "--file=archive.tar"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}
