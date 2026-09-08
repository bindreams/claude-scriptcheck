use super::find::*;
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

#[allow(dead_code)]
fn r(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn find_single_path() {
    let result = FindParser
        .parse(&["/tmp", "-name", "*.txt"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn find_multiple_paths() {
    let result = FindParser
        .parse(&["/tmp", "/var", "-type", "f"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp", "/var"]));
}

#[skuld::test]
fn find_relative_path() {
    let result = FindParser
        .parse(&[".", "-name", "*.rs"], "/home/user")
        .unwrap();
    assert_eq!(result.reads, sub(&["/home/user/."]));
}

#[skuld::test]
fn find_no_path_expression_first() {
    // No path operand: find walks the working directory.
    let result = FindParser.parse(&["-name", "*.txt"], "/tmp").unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
}

#[skuld::test]
fn find_with_negation() {
    let result = FindParser
        .parse(&["/tmp", "!", "-name", "*.log"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
}

#[skuld::test]
fn find_with_parens() {
    let result = FindParser
        .parse(&["/tmp", "(", "-name", "*.txt", ")"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
}

#[skuld::test]
fn find_exec() {
    let result = FindParser
        .parse(
            &["/tmp", "-name", "*.txt", "-exec", "rm", "{}", ";"],
            "/cwd",
        )
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
}

#[skuld::test]
fn find_maxdepth_before_path() {
    // find -maxdepth 1 . — maxdepth is an expression, so no path operand is
    // recognised and the walk is attributed to the working directory.
    let result = FindParser.parse(&["-maxdepth", "1", "."], "/tmp").unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
}

#[skuld::test]
fn find_newer_variant() {
    let result = FindParser
        .parse(&["/tmp", "-newermt", "2023-01-01"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp"]));
}

// Recursion scopes ====================================================================================================

#[skuld::test]
fn find_search_path_is_subtree() {
    let result = FindParser
        .parse(&["/tmp/src", "-type", "f"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp/src"]));
}

#[skuld::test]
fn find_no_path_reads_cwd() {
    let result = FindParser.parse(&["-name", "*.rs"], "/tmp/proj").unwrap();
    assert_eq!(result.reads, sub(&["/tmp/proj"]));
}

#[skuld::test]
fn find_dash_l_is_following_and_not_a_path() {
    let result = FindParser
        .parse(&["-L", "/tmp/src", "-type", "f"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, unbounded(&["/tmp/src"]));
}

#[skuld::test]
fn find_delete_writes_the_search_subtree() {
    let result = FindParser
        .parse(&["/tmp/src", "-name", "*.tmp", "-delete"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp/src"]));
    assert_eq!(result.writes, sub(&["/tmp/src"]));
}
