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

#[skuld::test]
fn find_expression_follow_is_following() {
    // `-follow` is the expression-position spelling of `-L`, and it must not
    // be mistaken for a search path.
    let result = FindParser
        .parse(&[".", "-follow", "-name", "*.txt"], "/repro")
        .unwrap();
    assert_eq!(result.reads, unbounded(&["/repro/."]));
}

#[skuld::test]
fn find_trailing_debug_flag_does_not_panic() {
    // `-D` takes a value that may be missing when the user types a bare `-D`.
    let result = FindParser.parse(&["-D"], "/repro").unwrap();
    assert_eq!(result.reads, sub(&["/repro"]));
}

#[skuld::test]
fn find_debug_flag_consumes_its_value() {
    let result = FindParser
        .parse(&["-D", "tree", "/tmp/src"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, sub(&["/tmp/src"]));
}

// Program execution ===================================================================================================

#[skuld::test]
fn find_exec_requires_bash_rule() {
    let result = FindParser
        .parse(
            &[
                ".",
                "-type",
                "f",
                "-exec",
                "sh",
                "-c",
                "curl -T {} url",
                ";",
            ],
            "/cwd",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn find_execdir_requires_bash_rule() {
    let result = FindParser
        .parse(&[".", "-execdir", "rm", "{}", ";"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn find_ok_requires_bash_rule() {
    let result = FindParser
        .parse(&[".", "-ok", "rm", "{}", ";"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn find_okdir_requires_bash_rule() {
    let result = FindParser
        .parse(&[".", "-okdir", "rm", "{}", ";"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn find_without_exec_stays_file_only() {
    let result = FindParser.parse(&[".", "-type", "f"], "/cwd").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn find_exec_still_reads_the_walked_subtree() {
    // The Bash demand is added to the walk's scope, not substituted for it, so
    // deny rules under the walk keep firing.
    let result = FindParser
        .parse(&[".", "-exec", "rm", "{}", ";"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/cwd/."]));
}

// Writing predicates ==================================================================================================

fn exact(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|p| AccessScope::Exact(p.to_string()))
        .collect()
}

#[skuld::test]
fn find_fprint_records_write() {
    let result = FindParser
        .parse(&[".", "-fprint", "/tmp/leak"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, exact(&["/tmp/leak"]));
}

#[skuld::test]
fn find_fprint0_records_write() {
    let result = FindParser
        .parse(&[".", "-fprint0", "/tmp/leak"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, exact(&["/tmp/leak"]));
}

#[skuld::test]
fn find_fls_records_write() {
    let result = FindParser
        .parse(&[".", "-fls", "/tmp/leak"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, exact(&["/tmp/leak"]));
}

#[skuld::test]
fn find_fprintf_records_only_the_file_operand() {
    // `-fprintf FILE FORMAT` — the format string is not a path.
    let result = FindParser
        .parse(&[".", "-fprintf", "/tmp/leak", "%p\\n"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, exact(&["/tmp/leak"]));
}

#[skuld::test]
fn find_fprint_target_is_relative_to_cwd() {
    let result = FindParser
        .parse(&[".", "-fprint", "leak"], "/home/user")
        .unwrap();
    assert_eq!(result.writes, exact(&["/home/user/leak"]));
}

#[skuld::test]
fn find_fprint_without_operand_records_nothing() {
    let result = FindParser.parse(&[".", "-fprint"], "/cwd").unwrap();
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn find_multiple_writing_predicates_record_each() {
    let result = FindParser
        .parse(&[".", "-fprint", "/tmp/a", "-fls", "/tmp/b"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, exact(&["/tmp/a", "/tmp/b"]));
}

#[skuld::test]
fn find_delete_still_writes_the_subtree() {
    let result = FindParser.parse(&[".", "-delete"], "/cwd").unwrap();
    assert_eq!(result.writes, sub(&["/cwd/."]));
}

#[skuld::test]
fn find_delete_and_fprint_record_both() {
    let result = FindParser
        .parse(&[".", "-delete", "-fprint", "/tmp/leak"], "/cwd")
        .unwrap();
    assert_eq!(
        result.writes,
        [sub(&["/cwd/."]), exact(&["/tmp/leak"])].concat(),
    );
}
