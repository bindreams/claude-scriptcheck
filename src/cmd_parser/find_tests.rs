use super::find::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn find_single_path() {
    let result = FindParser.parse(&["/tmp", "-name", "*.txt"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn find_multiple_paths() {
    let result = FindParser.parse(&["/tmp", "/var", "-type", "f"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp", "/var"]));
}

#[skuld::test]
fn find_relative_path() {
    let result = FindParser.parse(&[".", "-name", "*.rs"], "/home/user").unwrap();
    assert_eq!(result.reads, r(&["/home/user/."]));
}

#[skuld::test]
fn find_no_path_expression_first() {
    let result = FindParser.parse(&["-name", "*.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn find_with_negation() {
    let result = FindParser.parse(&["/tmp", "!", "-name", "*.log"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

#[skuld::test]
fn find_with_parens() {
    let result = FindParser.parse(&["/tmp", "(", "-name", "*.txt", ")"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

#[skuld::test]
fn find_exec() {
    let result = FindParser.parse(
        &["/tmp", "-name", "*.txt", "-exec", "rm", "{}", ";"],
        "/cwd",
    ).unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

#[skuld::test]
fn find_maxdepth_before_path() {
    // find -maxdepth 1 . — maxdepth is an expression, so no paths extracted
    let result = FindParser.parse(&["-maxdepth", "1", "."], "/tmp").unwrap();
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn find_newer_variant() {
    let result = FindParser.parse(&["/tmp", "-newermt", "2023-01-01"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}
