use super::sed::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn w(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn sed_basic_read() {
    let result = SedParser
        .parse(&["s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn sed_inplace_is_write() {
    let result = SedParser
        .parse(&["-i", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_inplace_with_suffix() {
    let result = SedParser
        .parse(&["-i.bak", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_inplace_long_form() {
    let result = SedParser
        .parse(&["--in-place", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_inplace_long_form_with_suffix() {
    let result = SedParser
        .parse(&["--in-place=.bak", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_e_flag_consumes_script() {
    let result = SedParser
        .parse(&["-e", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_multiple_e_flags() {
    let result = SedParser
        .parse(
            &["-e", "s/foo/bar/", "-e", "s/baz/qux/", "file.txt"],
            "/tmp",
        )
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_f_flag_is_read() {
    let result = SedParser
        .parse(&["-f", "script.sed", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sed", "/tmp/file.txt"]));
}

#[skuld::test]
fn sed_n_flag_is_boolean() {
    let result = SedParser
        .parse(&["-n", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_combined_flags_ni() {
    let result = SedParser
        .parse(&["-ni", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_combined_flags_ne() {
    let result = SedParser
        .parse(&["-ne", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_script_only_no_files() {
    let result = SedParser.parse(&["s/foo/bar/"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn sed_inplace_multiple_files() {
    let result = SedParser
        .parse(&["-i", "s/foo/bar/", "a.txt", "b.txt"], "/tmp")
        .unwrap();
    assert_eq!(result.writes, w(&["/tmp/a.txt", "/tmp/b.txt"]));
}

#[skuld::test]
fn sed_unknown_flag_fails() {
    let result = SedParser.parse(&["--bogus", "s/foo/bar/", "file.txt"], "/tmp");
    assert!(result.is_err());
}

#[skuld::test]
fn sed_double_dash_files() {
    let result = SedParser
        .parse(&["-e", "s/a/b/", "--", "-weird-file"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/-weird-file"]));
}
