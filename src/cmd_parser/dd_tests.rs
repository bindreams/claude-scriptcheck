use super::dd::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn w(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[test]
fn dd_basic() {
    let result = DdParser.parse(&["if=input.bin", "of=output.bin", "bs=4096"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/input.bin"]));
    assert_eq!(result.writes, w(&["/tmp/output.bin"]));
}

#[test]
fn dd_only_input() {
    let result = DdParser.parse(&["if=/dev/urandom", "bs=1M", "count=1"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/dev/urandom"]));
    assert!(result.writes.is_empty());
}

#[test]
fn dd_only_output() {
    let result = DdParser.parse(&["of=/tmp/zeros", "bs=1M", "count=100"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/zeros"]));
}

#[test]
fn dd_unknown_arg_fails() {
    let result = DdParser.parse(&["if=input", "badarg"], "/tmp");
    assert!(result.is_err());
}
