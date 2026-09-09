use super::ls::*;
use super::CommandParser;
use crate::file_access::AccessScope;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

fn sub(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Subtree(s.to_string()))
        .collect()
}

#[skuld::test]
fn ls_operand_is_exact() {
    let result = LsParser.parse(&["-la", "src"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/src"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn ls_recursive_operand_is_subtree() {
    let result = LsParser.parse(&["-R", "src"], "/tmp").unwrap();
    assert_eq!(result.reads, sub(&["/tmp/src"]));
}

#[skuld::test]
fn ls_long_recursive_flag_is_subtree() {
    let result = LsParser.parse(&["--recursive", "src"], "/tmp").unwrap();
    assert_eq!(result.reads, sub(&["/tmp/src"]));
}

#[skuld::test]
fn ls_no_operand_reads_cwd() {
    let result = LsParser.parse(&[], "/tmp/proj").unwrap();
    assert_eq!(result.reads, r(&["/tmp/proj"]));
}

#[skuld::test]
fn ls_no_operand_recursive_reads_cwd_subtree() {
    let result = LsParser.parse(&["-R"], "/tmp/proj").unwrap();
    assert_eq!(result.reads, sub(&["/tmp/proj"]));
}

#[skuld::test]
fn ls_multiple_operands() {
    let result = LsParser.parse(&["a", "b"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/a", "/tmp/b"]));
}

#[skuld::test]
fn ls_common_flags_parse() {
    for args in [
        vec!["-lah"],
        vec!["-1"],
        vec!["--color=auto"],
        vec!["--time-style=long-iso"],
        vec!["-ltr"],
        vec!["-d", "src"],
        vec!["--group-directories-first"],
        vec!["-I", "*.tmp", "src"],
    ] {
        assert!(
            LsParser.parse(&args, "/tmp").is_ok(),
            "failed to parse `ls {}`",
            args.join(" "),
        );
    }
}

#[skuld::test]
fn ls_recursive_dereference_is_following() {
    let result = LsParser.parse(&["-RL", "src"], "/tmp").unwrap();
    assert_eq!(
        result.reads,
        vec![AccessScope::UnboundedSubtree("/tmp/src".into())],
    );
}

#[skuld::test]
fn ls_dereference_without_recursion_stays_exact() {
    let result = LsParser.parse(&["-L", "src"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/src"]));
}
