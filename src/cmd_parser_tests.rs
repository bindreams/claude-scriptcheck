use crate::cmd_parser::*;
use pretty_assertions::assert_eq;


#[test]
fn unknown_command_returns_empty() {
    let result = parse_file_accesses("my-custom-tool", &[Some("arg1".into())], "/tmp");
    match result {
        CmdParseResult::Parsed(cfa) => {
            assert!(cfa.reads.is_empty());
            assert!(cfa.writes.is_empty());
        }
        _ => panic!("expected Parsed"),
    }
}

#[test]
fn no_file_access_command_returns_empty() {
    let result = parse_file_accesses("echo", &[Some("hello".into())], "/tmp");
    match result {
        CmdParseResult::Parsed(cfa) => {
            assert!(cfa.reads.is_empty());
            assert!(cfa.writes.is_empty());
        }
        _ => panic!("expected Parsed"),
    }
}

#[test]
fn sentinel_filtered_from_reads() {
    let cfa = CommandFileAccesses {
        reads: vec![
            "/tmp/real.txt".into(),
            format!("/tmp/{SENTINEL}"),
        ],
        writes: vec![],
        inline_script_start: None,
    };
    let filtered = cfa.filter_sentinel(SENTINEL);
    assert_eq!(filtered.reads, vec!["/tmp/real.txt"]);
}

#[test]
fn sentinel_filtered_from_writes() {
    let cfa = CommandFileAccesses {
        reads: vec![],
        writes: vec![
            "/tmp/real.txt".into(),
            format!("/tmp/{SENTINEL}"),
        ],
        inline_script_start: None,
    };
    let filtered = cfa.filter_sentinel(SENTINEL);
    assert_eq!(filtered.writes, vec!["/tmp/real.txt"]);
}

#[test]
fn dynamic_arg_filtered_via_sentinel() {
    // cp $SRC dest.txt → only dest.txt should appear as Write
    let result = parse_file_accesses(
        "cp",
        &[None, Some("dest.txt".into())],
        "/tmp",
    );
    match result {
        CmdParseResult::Parsed(cfa) => {
            assert!(cfa.reads.is_empty(), "sentinel read should be filtered");
            assert_eq!(cfa.writes, vec!["/tmp/dest.txt"]);
        }
        _ => panic!("expected Parsed"),
    }
}
