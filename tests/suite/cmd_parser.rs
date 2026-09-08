use claude_scriptcheck::cmd_parser::*;
use claude_scriptcheck::file_access::AccessScope;
use pretty_assertions::assert_eq;

#[skuld::test]
fn unknown_command_returns_empty() {
    let result = parse_file_accesses(
        "my-custom-tool",
        &[ResolvedArg::Static("arg1".into())],
        "/tmp",
    );
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
fn unresolved_arg_marks_read_scope() {
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
    let filtered = cfa.mark_unresolved(&[ResolvedArg::Unresolved("$SRC".into())]);
    assert_eq!(
        filtered.reads,
        vec![
            AccessScope::Exact("/tmp/real.txt".into()),
            AccessScope::Unresolved("$SRC".into()),
        ],
    );
}

#[skuld::test]
fn unresolved_arg_marks_write_scope() {
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
    let filtered = cfa.mark_unresolved(&[ResolvedArg::Unresolved("$SRC".into())]);
    assert_eq!(
        filtered.writes,
        vec![
            AccessScope::Exact("/tmp/real.txt".into()),
            AccessScope::Unresolved("$SRC".into()),
        ],
    );
}

#[skuld::test]
fn dynamic_arg_marked_unresolved() {
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
            assert_eq!(cfa.reads, vec![AccessScope::Unresolved("$SRC".into())]);
            assert_eq!(cfa.writes, vec![AccessScope::Exact("/tmp/dest.txt".into())]);
        }
        _ => panic!("expected Parsed"),
    }
}

#[skuld::test]
fn sentinel_index_delimiter_prevents_prefix_collision() {
    // The trailing `__` is what keeps index 1 from matching inside index 11.
    assert!(!sentinel(11).contains(&sentinel(1)));

    let mut args: Vec<ResolvedArg> = (0..12)
        .map(|i| ResolvedArg::Static(format!("s{i}")))
        .collect();
    args[1] = ResolvedArg::Unresolved("$ONE".into());
    args[11] = ResolvedArg::Unresolved("$ELEVEN".into());

    let cfa = CommandFileAccesses {
        reads: vec![
            AccessScope::Exact(format!("/tmp/{}", sentinel(1))),
            AccessScope::Exact(format!("/tmp/{}", sentinel(11))),
        ],
        ..Default::default()
    };
    assert_eq!(
        cfa.mark_unresolved(&args).reads,
        vec![
            AccessScope::Unresolved("$ONE".into()),
            AccessScope::Unresolved("$ELEVEN".into()),
        ],
    );
}

#[skuld::test]
fn sentinel_prefix_in_a_static_arg_alone_is_left_alone() {
    // No argument is unresolved, so nothing was substituted and nothing is
    // scanned back out: a file genuinely named like a sentinel keeps its scope.
    let result = parse_file_accesses("cat", &[ResolvedArg::Static(sentinel(0))], "/tmp");
    match result {
        CmdParseResult::Parsed(cfa) => assert_eq!(
            cfa.reads,
            vec![AccessScope::Exact(format!("/tmp/{}", sentinel(0)))],
        ),
        _ => panic!("expected Parsed"),
    }
}

#[skuld::test]
fn lowest_sentinel_index_wins() {
    let args = [
        ResolvedArg::Unresolved("$FIRST".into()),
        ResolvedArg::Unresolved("$SECOND".into()),
    ];
    let cfa = CommandFileAccesses {
        reads: vec![AccessScope::Exact(format!(
            "/tmp/{}/{}",
            sentinel(0),
            sentinel(1)
        ))],
        ..Default::default()
    };
    assert_eq!(
        cfa.mark_unresolved(&args).reads,
        vec![AccessScope::Unresolved("$FIRST".into())],
    );
}

#[skuld::test]
fn recursive_scope_with_sentinel_collapses_to_unresolved() {
    // The recursion tag is discarded: `Unresolved` already satisfies no allow
    // rule, which is the strongest of the outcomes it replaces.
    let args = [ResolvedArg::Unresolved("$DIR".into())];
    let cfa = CommandFileAccesses {
        reads: vec![AccessScope::Subtree(format!("/tmp/{}", sentinel(0)))],
        writes: vec![AccessScope::UnboundedSubtree(format!(
            "/tmp/{}",
            sentinel(0)
        ))],
        ..Default::default()
    };
    let marked = cfa.mark_unresolved(&args);
    assert_eq!(marked.reads, vec![AccessScope::Unresolved("$DIR".into())]);
    assert_eq!(marked.writes, vec![AccessScope::Unresolved("$DIR".into())]);
}

#[skuld::test]
fn sentinel_index_pointing_at_a_static_arg_leaves_the_scope_alone() {
    // String provenance can collide. When it does, the honest path stays put so
    // its deny evaluation keeps working; the cost is bounded to one mislabel.
    let args = [ResolvedArg::Static("plain".into())];
    let cfa = CommandFileAccesses {
        reads: vec![AccessScope::Exact(format!("/tmp/{}", sentinel(0)))],
        ..Default::default()
    };
    assert_eq!(
        cfa.mark_unresolved(&args).reads,
        vec![AccessScope::Exact(format!("/tmp/{}", sentinel(0)))],
    );
}
