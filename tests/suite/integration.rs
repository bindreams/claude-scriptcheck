use claude_scriptcheck::checker::Decision;
use claude_scriptcheck::{checker, permission, settings};

/// Parse and check a command against the user's actual settings.
fn check_command(command: &str, cwd: &str) -> Decision {
    let permissions = settings::load_settings(cwd, cwd);
    let parsed_perms = permission::parse_rules(&permissions);
    let program = thaum::parse_with(command, thaum::Dialect::Bash).unwrap();
    checker::check_program(&program, &parsed_perms, cwd).decision
}

// ── Logic tests (via library API) ───────────────────────────────────────────

#[skuld::test]
fn allowed_command_from_settings() {
    assert_eq!(check_command("ls -la /tmp", "/tmp"), Decision::Allow);
}

#[skuld::test]
fn unallowed_command_asks() {
    assert!(matches!(
        check_command("my-totally-unknown-command --flag", "/tmp"),
        Decision::Ask(_)
    ));
}

#[skuld::test]
fn redirect_to_allowed_path() {
    assert_eq!(
        check_command("echo hello > /tmp/claude/test-output.txt", "/tmp"),
        Decision::Allow,
    );
}

#[skuld::test]
fn redirect_to_disallowed_path() {
    let decision = check_command("echo hello > /etc/test-output.txt", "/tmp");
    assert!(
        matches!(decision, Decision::Ask(ref rules) if rules.iter().any(|r| r.contains("Write(")))
    );
}

#[skuld::test]
fn eval_always_asks() {
    assert!(matches!(
        check_command("eval echo hello", "/tmp"),
        Decision::Ask(_)
    ));
}

#[skuld::test]
fn pipeline_allowed() {
    assert_eq!(check_command("echo hello | wc -l", "/tmp"), Decision::Allow);
}

#[skuld::test]
fn git_status_allowed() {
    assert_eq!(check_command("git status --short", "/tmp"), Decision::Allow,);
}

#[skuld::test]
fn cargo_check_allowed() {
    assert_eq!(
        check_command("cargo check --all-targets", "/tmp"),
        Decision::Allow,
    );
}

#[skuld::test]
fn unparseable_shell_is_error() {
    assert!(thaum::parse_with("if then fi else", thaum::Dialect::Bash).is_err());
}

// ── Binary I/O tests (must invoke the actual binary) ────────────────────────

use std::io::Write;
use std::process::{Command, Stdio};

fn run_binary(stdin_bytes: &[u8]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start binary");

    child.stdin.take().unwrap().write_all(stdin_bytes).unwrap();

    child.wait_with_output().unwrap()
}

fn hook_json(tool_name: &str, command: &str) -> Vec<u8> {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command },
        "tool_use_id": "toolu_test"
    })
    .to_string()
    .into_bytes()
}

fn file_tool_json(tool_name: &str, file_path: &str) -> Vec<u8> {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "file_path": file_path },
        "tool_use_id": "toolu_test"
    })
    .to_string()
    .into_bytes()
}

fn search_tool_json(tool_name: &str, path: Option<&str>, pattern: &str) -> Vec<u8> {
    let mut tool_input = serde_json::json!({ "pattern": pattern });
    if let Some(p) = path {
        tool_input["path"] = serde_json::json!(p);
    }
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "toolu_test"
    })
    .to_string()
    .into_bytes()
}

fn parse_decision(output: &std::process::Output) -> String {
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid JSON: {e}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .expect("missing permissionDecision field")
        .to_string()
}

#[skuld::test]
fn unsupported_tool_exits_cleanly() {
    let output = run_binary(&hook_json("Agent", "anything"));
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[skuld::test]
fn empty_command_exits_cleanly() {
    let output = run_binary(&hook_json("Bash", ""));
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[skuld::test]
fn invalid_json_exits_with_error() {
    let output = run_binary(b"not json at all");
    assert_eq!(output.status.code(), Some(2));
}

// ── Non-Bash tool tests ─────────────────────────────────────────────────────

#[skuld::test]
fn grep_tool_produces_decision() {
    let output = run_binary(&search_tool_json("Grep", Some("/tmp"), "pattern"));
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "Grep should produce JSON output");
    let decision = parse_decision(&output);
    assert!(
        decision == "allow" || decision == "ask",
        "expected allow or ask, got {decision}",
    );
}

#[skuld::test]
fn read_tool_produces_decision() {
    let output = run_binary(&file_tool_json("Read", "/tmp/test.txt"));
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "Read should produce JSON output");
    parse_decision(&output); // just verify it parses
}

#[skuld::test]
fn write_tool_produces_decision() {
    let output = run_binary(&file_tool_json("Write", "/tmp/test.txt"));
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !output.stdout.is_empty(),
        "Write should produce JSON output"
    );
    parse_decision(&output);
}

#[skuld::test]
fn edit_tool_produces_decision() {
    let output = run_binary(&file_tool_json("Edit", "/tmp/test.txt"));
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "Edit should produce JSON output");
    parse_decision(&output);
}

#[skuld::test]
fn glob_tool_produces_decision() {
    let output = run_binary(&search_tool_json("Glob", Some("/tmp"), "**/*.txt"));
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "Glob should produce JSON output");
    parse_decision(&output);
}

#[skuld::test]
fn grep_no_path_defaults_to_cwd() {
    let output = run_binary(&search_tool_json("Grep", None, "pattern"));
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !output.stdout.is_empty(),
        "Grep with no path should still produce JSON output"
    );
    parse_decision(&output);
}

#[skuld::test]
fn file_tool_missing_path_asks() {
    for tool in ["Read", "Write", "Edit"] {
        let input = serde_json::json!({
            "session_id": "test-session",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {},
            "tool_use_id": "toolu_test"
        })
        .to_string()
        .into_bytes();
        let output = run_binary(&input);
        assert_eq!(output.status.code(), Some(0), "{tool} should exit 0");
        let decision = parse_decision(&output);
        assert_eq!(decision, "ask", "{tool} with no file_path should ask");
    }
}
