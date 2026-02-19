use std::io::Write;
use std::process::{Command, Stdio};

fn run_hook(tool_name: &str, command: &str, cwd: &str) -> (String, i32) {
    let input = serde_json::json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "command": command },
        "tool_use_id": "toolu_test"
    });

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start binary");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let code = output.status.code().unwrap_or(-1);
    (stdout, code)
}

fn parse_decision(stdout: &str) -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(stdout).unwrap();
    let decision = v["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap()
        .to_string();
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_string();
    (decision, reason)
}

#[test]
fn non_bash_tool_exits_cleanly() {
    let (stdout, code) = run_hook("Read", "anything", "/tmp");
    assert_eq!(code, 0);
    assert!(stdout.is_empty(), "Non-Bash tool should produce no output");
}

#[test]
fn empty_command_allows() {
    let (stdout, code) = run_hook("Bash", "", "/tmp");
    assert_eq!(code, 0);
    assert!(stdout.is_empty(), "Empty command should produce no output (implicit allow)");
}

#[test]
fn allowed_command_from_settings() {
    // This test uses the actual user settings. `ls -la` should be allowed
    // because the global settings contain Bash(ls *).
    let (stdout, code) = run_hook("Bash", "ls -la /tmp", "/tmp");
    assert_eq!(code, 0);
    if !stdout.is_empty() {
        let (decision, _) = parse_decision(&stdout);
        assert_eq!(decision, "allow");
    }
}

#[test]
fn unallowed_command_asks() {
    // A command that is not in any allow list
    let (stdout, code) = run_hook("Bash", "my-totally-unknown-command --flag", "/tmp");
    assert_eq!(code, 0);
    assert!(!stdout.is_empty());
    let (decision, reason) = parse_decision(&stdout);
    assert_eq!(decision, "ask");
    assert!(reason.contains("Missing permission rules"));
}

#[test]
fn redirect_to_allowed_path() {
    // echo is allowed by settings, /tmp/claude/** is writable
    let (stdout, code) = run_hook("Bash", "echo hello > /tmp/claude/test-output.txt", "/tmp");
    assert_eq!(code, 0);
    if !stdout.is_empty() {
        let (decision, _) = parse_decision(&stdout);
        assert_eq!(decision, "allow");
    }
}

#[test]
fn redirect_to_disallowed_path() {
    // echo is allowed, but /etc/ is not writable
    let (stdout, code) = run_hook("Bash", "echo hello > /etc/test-output.txt", "/tmp");
    assert_eq!(code, 0);
    assert!(!stdout.is_empty());
    let (decision, reason) = parse_decision(&stdout);
    assert_eq!(decision, "ask");
    assert!(reason.contains("Write("));
}

#[test]
fn eval_always_asks() {
    let (stdout, code) = run_hook("Bash", "eval echo hello", "/tmp");
    assert_eq!(code, 0);
    assert!(!stdout.is_empty());
    let (decision, _) = parse_decision(&stdout);
    assert_eq!(decision, "ask");
}

#[test]
fn pipeline_allowed() {
    // echo and wc are allowed in settings; wc with no file args just reads stdin
    let (stdout, code) = run_hook("Bash", "echo hello | wc -l", "/tmp");
    assert_eq!(code, 0);
    if !stdout.is_empty() {
        let (decision, _) = parse_decision(&stdout);
        assert_eq!(decision, "allow");
    }
}

#[test]
fn git_status_allowed() {
    let (stdout, code) = run_hook("Bash", "git status --short", "/tmp");
    assert_eq!(code, 0);
    if !stdout.is_empty() {
        let (decision, _) = parse_decision(&stdout);
        assert_eq!(decision, "allow");
    }
}

#[test]
fn cargo_check_allowed() {
    let (stdout, code) = run_hook("Bash", "cargo check --all-targets", "/tmp");
    assert_eq!(code, 0);
    if !stdout.is_empty() {
        let (decision, _) = parse_decision(&stdout);
        assert_eq!(decision, "allow");
    }
}

#[test]
fn invalid_json_exits_with_error() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start binary");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"not json at all")
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn unparseable_shell_asks() {
    // This is syntactically invalid shell
    let (stdout, code) = run_hook("Bash", "if then fi else", "/tmp");
    assert_eq!(code, 0);
    if !stdout.is_empty() {
        let (decision, reason) = parse_decision(&stdout);
        assert_eq!(decision, "ask");
        assert!(reason.contains("parsed"));
    }
}
