use claude_scriptcheck::cmd_parser::*;
use claude_scriptcheck::file_access::AccessScope;
use pretty_assertions::assert_eq;

#[skuld::test]
fn unknown_command_returns_empty() {
    let result = parse_file_accesses("my-custom-tool", &[ResolvedArg::Static("arg1".into())], "/tmp");
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
    let result = parse_file_accesses("echo", &[ResolvedArg::Static("hello".into())], "/tmp");
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
            AccessScope::Exact(format!("/tmp/{}", sentinel(0))),
        ],
        writes: vec![],
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    };
    let filtered = cfa.filter_sentinels(&[ResolvedArg::Unresolved("$SRC".into())]);
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
            AccessScope::Exact(format!("/tmp/{}", sentinel(0))),
        ],
        inline_script_start: None,
        file_only: None,
        ..Default::default()
    };
    let filtered = cfa.filter_sentinels(&[ResolvedArg::Unresolved("$SRC".into())]);
    assert_eq!(
        filtered.writes,
        vec![AccessScope::Exact("/tmp/real.txt".into())]
    );
}

#[skuld::test]
fn dynamic_arg_filtered_via_sentinel() {
    let result = parse_file_accesses(
        "cp",
        &[
            ResolvedArg::Unresolved("$SRC".into()),
            ResolvedArg::Static("dest.txt".into()),
        ],
        "/tmp",
    );
    match result {
        CmdParseResult::Parsed(cfa) => {
            assert!(cfa.reads.is_empty(), "sentinel read should be filtered");
            assert_eq!(cfa.writes, vec![AccessScope::Exact("/tmp/dest.txt".into())]);
        }
        _ => panic!("expected Parsed"),
    }
}

#[skuld::test]
fn sentinel_index_delimiter_prevents_prefix_collision() {
    // The trailing `__` is what keeps index 1 from matching inside index 11.
    assert!(!sentinel(11).contains(&sentinel(1)));

    let mut args: Vec<ResolvedArg> = (0..12).map(|i| ResolvedArg::Static(format!("s{i}"))).collect();
    args[1] = ResolvedArg::Unresolved("$ONE".into());
    args[11] = ResolvedArg::Unresolved("$ELEVEN".into());

    let cfa = CommandFileAccesses {
        reads: vec![
            AccessScope::Exact(format!("/tmp/{}", sentinel(1))),
            AccessScope::Exact(format!("/tmp/{}", sentinel(11))),
        ],
        ..Default::default()
    };
    assert!(cfa.filter_sentinels(&args).reads.is_empty());
}

#[skuld::test]
fn sentinel_prefix_in_a_static_arg_alone_is_left_alone() {
    // No argument is unresolved, so nothing was substituted and nothing is
    // scanned back out: a file genuinely named like a sentinel keeps its scope.
    let result = parse_file_accesses(
        "cat",
        &[ResolvedArg::Static(sentinel(0))],
        "/tmp",
    );
    match result {
        CmdParseResult::Parsed(cfa) => assert_eq!(
            cfa.reads,
            vec![AccessScope::Exact(format!("/tmp/{}", sentinel(0)))],
        ),
        _ => panic!("expected Parsed"),
    }
}
