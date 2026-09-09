use claude_scriptcheck::cmd_parser::*;
use claude_scriptcheck::file_access::AccessScope;
use pretty_assertions::assert_eq;

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
fn sentinel_filtered_from_reads() {
    let cfa = CommandFileAccesses {
        reads: vec![
            "/tmp/real.txt".into(),
            AccessScope::Exact(format!("/tmp/{SENTINEL}")),
        ],
        writes: vec![],
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    };
    let filtered = cfa.filter_sentinel(SENTINEL);
    assert_eq!(
        filtered.reads,
        vec![AccessScope::Exact("/tmp/real.txt".into())]
    );
}

#[skuld::test]
fn sentinel_filtered_from_writes() {
    let cfa = CommandFileAccesses {
        reads: vec![],
        writes: vec![
            "/tmp/real.txt".into(),
            AccessScope::Exact(format!("/tmp/{SENTINEL}")),
        ],
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    };
    let filtered = cfa.filter_sentinel(SENTINEL);
    assert_eq!(
        filtered.writes,
        vec![AccessScope::Exact("/tmp/real.txt".into())]
    );
}

#[skuld::test]
fn dynamic_arg_filtered_via_sentinel() {
    let result = parse_file_accesses("cp", &[None, Some("dest.txt".into())], "/tmp");
    match result {
        CmdParseResult::Parsed(cfa) => {
            assert!(cfa.reads.is_empty(), "sentinel read should be filtered");
            assert_eq!(cfa.writes, vec![AccessScope::Exact("/tmp/dest.txt".into())]);
        }
        _ => panic!("expected Parsed"),
    }
}
