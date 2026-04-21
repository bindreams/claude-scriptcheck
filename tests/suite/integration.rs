use claude_scriptcheck::checker::{CheckResult, Decision};
use claude_scriptcheck::{checker, permission, settings};

/// Parse and check a command against the user's actual settings.
fn check_command(command: &str, cwd: &str) -> CheckResult {
    let loaded = settings::load_settings(cwd, cwd);
    let parsed_perms = permission::parse_rules(&loaded.permissions);
    let program = thaum::parse_with(command, thaum::Dialect::Bash).unwrap();
    checker::check_program(&program, &parsed_perms, cwd)
}

// ── Logic tests (via library API) ───────────────────────────────────────────

#[skuld::test]
fn allowed_command_from_settings() {
    assert_eq!(
        check_command("ls -la /tmp", "/tmp").decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn unallowed_command_asks() {
    assert_eq!(
        check_command("my-totally-unknown-command --flag", "/tmp").decision,
        Decision::Ask,
    );
}

#[skuld::test]
fn redirect_to_allowed_path() {
    assert_eq!(
        check_command("echo hello > /tmp/claude/test-output.txt", "/tmp").decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn redirect_to_disallowed_path() {
    let result = check_command("echo hello > /etc/test-output.txt", "/tmp");
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result.missing_rules.iter().any(|r| r.contains("Write(")),
        "expected Write rule in missing, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn eval_always_asks() {
    assert_eq!(
        check_command("eval echo hello", "/tmp").decision,
        Decision::Ask,
    );
}

#[skuld::test]
fn pipeline_allowed() {
    assert_eq!(
        check_command("echo hello | wc -l", "/tmp").decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn git_status_allowed() {
    assert_eq!(
        check_command("git status --short", "/tmp").decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn cargo_check_allowed() {
    assert_eq!(
        check_command("cargo check --all-targets", "/tmp").decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn unparseable_shell_is_error() {
    assert!(thaum::parse_with("if then fi else", thaum::Dialect::Bash).is_err());
}

// ── Binary I/O tests (must invoke the actual binary) ────────────────────────

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counter for allocating unique ephemeral log paths per subprocess call.
static TEST_LOG_COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII cleanup for the ephemeral log file written by an isolated subprocess.
struct IsolatedLog(PathBuf);

impl Drop for IsolatedLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Point the child binary at a nonexistent home and an ephemeral log file so it
/// cannot read the developer's real `~/.claude/settings.json` nor pollute their
/// real `log.yaml`. Returns an `IsolatedLog` guard that removes the ephemeral
/// log file when dropped.
///
/// `HOME` isolation works on Unix (via `dirs::home_dir()`). On Windows, `dirs`
/// uses `SHGetKnownFolderPath(FOLDERID_Profile)` and ignores `HOME`, so the hook
/// also consults `CLAUDE_SCRIPTCHECK_HOOK_HOME` — which we set here. Callers may
/// set `CLAUDE_PROJECT_DIR` themselves; this helper never touches it.
fn apply_test_isolation(cmd: &mut Command) -> IsolatedLog {
    let pid = std::process::id();
    let counter = TEST_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir();
    let isolated_home = base.join(format!(
        "claude-scriptcheck-test-home-{pid}-{counter}-nonexistent"
    ));
    let log_path = base.join(format!("claude-scriptcheck-test-log-{pid}-{counter}.yaml"));
    cmd.env("HOME", &isolated_home);
    cmd.env("CLAUDE_SCRIPTCHECK_HOOK_HOME", &isolated_home);
    cmd.env("CLAUDE_SCRIPTCHECK_LOG_PATH", &log_path);
    IsolatedLog(log_path)
}

fn run_binary(stdin_bytes: &[u8]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let mut cmd = Command::new(binary);
    let _log_guard = apply_test_isolation(&mut cmd);
    let mut child = cmd
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
    // With test isolation (no host settings leaked in), there is no Read rule
    // matching /tmp, so the verdict must be deterministic "ask". If this turns
    // back into "allow", the isolation is broken.
    assert_eq!(decision, "ask");
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

// ── Permission mode (acceptEdits) tests ─────────────────────────────────────

fn run_binary_with_env(stdin_bytes: &[u8], env: &[(&str, &str)]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let mut cmd = Command::new(binary);
    let _log_guard = apply_test_isolation(&mut cmd);
    // Caller-provided env vars are applied last so they can override isolation
    // (e.g. CLAUDE_PROJECT_DIR).
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start binary");

    child.stdin.take().unwrap().write_all(stdin_bytes).unwrap();
    child.wait_with_output().unwrap()
}

fn file_tool_json_with_mode(
    tool_name: &str,
    file_path: &str,
    cwd: &str,
    permission_mode: Option<&str>,
) -> Vec<u8> {
    let mut json = serde_json::json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": { "file_path": file_path },
        "tool_use_id": "toolu_test"
    });
    if let Some(mode) = permission_mode {
        json["permission_mode"] = serde_json::json!(mode);
    }
    json.to_string().into_bytes()
}

#[skuld::test]
fn accept_edits_allows_workspace_write(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    let file_in_workspace = format!("{project_root}/src/main.rs");
    std::fs::create_dir(dir.join("src")).unwrap();

    let input = file_tool_json_with_mode(
        "Edit",
        &file_in_workspace,
        &project_root,
        Some("acceptEdits"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "allow",
        "acceptEdits should auto-allow workspace edit"
    );
}

#[skuld::test]
fn accept_edits_allows_workspace_write_tool(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    let file_in_workspace = format!("{project_root}/output.txt");

    let input = file_tool_json_with_mode(
        "Write",
        &file_in_workspace,
        &project_root,
        Some("acceptEdits"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "allow",
        "acceptEdits should auto-allow workspace Write tool"
    );
}

#[skuld::test]
fn accept_edits_asks_outside_workspace(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    let file_outside = "/etc/passwd";

    let input = file_tool_json_with_mode("Edit", file_outside, &project_root, Some("acceptEdits"));
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "ask",
        "acceptEdits should not auto-allow outside workspace"
    );
}

#[skuld::test]
fn accept_edits_does_not_override_read(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    let file_outside = "/etc/passwd";

    let input = file_tool_json_with_mode("Read", file_outside, &project_root, Some("acceptEdits"));
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(decision, "ask", "acceptEdits should not auto-allow reads");
}

/// Positive test for `CLAUDE_SCRIPTCHECK_HOOK_HOME` — proves that settings
/// actually get loaded from the override location. The mock settings contain a
/// bare `"Read"` allow rule (which expands to `Read(**)`). If the override
/// silently fell back to `dirs::home_dir()` (the original Windows bug), no
/// such rule would match and the verdict would be `ask` instead of `allow`.
#[skuld::test]
fn hook_home_override_redirects_settings_loading(#[fixture(temp_dir)] dir: &std::path::Path) {
    let mock_home = dir;
    std::fs::create_dir_all(mock_home.join(".claude")).unwrap();
    std::fs::write(
        mock_home.join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Read"]}}"#,
    )
    .unwrap();

    // Use an unrelated project_root so project-level settings don't interfere.
    let project_root = std::env::temp_dir()
        .join(format!(
            "claude-scriptcheck-hook-home-override-pr-{}",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();

    let input = file_tool_json_with_mode("Read", "/etc/passwd", &project_root, None);
    let output = run_binary_with_env(
        &input,
        &[("CLAUDE_SCRIPTCHECK_HOOK_HOME", &mock_home.to_string_lossy())],
    );

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "allow",
        "CLAUDE_SCRIPTCHECK_HOOK_HOME must redirect settings loading"
    );
}

#[skuld::test]
fn missing_permission_mode_is_default(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    let file_in_workspace = format!("{project_root}/test.txt");

    let input = file_tool_json_with_mode("Edit", &file_in_workspace, &project_root, None);
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "ask",
        "without permission_mode, should ask for workspace edits"
    );
}

#[skuld::test]
fn default_mode_no_ephemeral_rules(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    let file_in_workspace = format!("{project_root}/test.txt");

    let input =
        file_tool_json_with_mode("Edit", &file_in_workspace, &project_root, Some("default"));
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "ask",
        "default mode should ask for workspace edits"
    );
}

// ── Permission mode (bypassPermissions) tests ───────────────────────────────

fn hook_json_with_mode(
    tool_name: &str,
    tool_input: serde_json::Value,
    cwd: &str,
    permission_mode: Option<&str>,
) -> Vec<u8> {
    let mut json = serde_json::json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "toolu_test"
    });
    if let Some(mode) = permission_mode {
        json["permission_mode"] = serde_json::json!(mode);
    }
    json.to_string().into_bytes()
}

fn parse_reason(output: &std::process::Output) -> String {
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid JSON: {e}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    json["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("missing permissionDecisionReason field")
        .to_string()
}

#[skuld::test]
fn bypass_allows_bash() {
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "unknown-cmd --flag"}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_allows_read() {
    let input = file_tool_json_with_mode("Read", "/etc/passwd", "/tmp", Some("bypassPermissions"));
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_allows_write() {
    let input = file_tool_json_with_mode("Write", "/etc/passwd", "/tmp", Some("bypassPermissions"));
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_allows_edit() {
    let input = file_tool_json_with_mode("Edit", "/etc/passwd", "/tmp", Some("bypassPermissions"));
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_allows_grep() {
    let input = hook_json_with_mode(
        "Grep",
        serde_json::json!({"pattern": "x", "path": "/etc"}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_allows_glob() {
    let input = hook_json_with_mode(
        "Glob",
        serde_json::json!({"pattern": "*.txt", "path": "/etc"}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_unknown_tool_silent_exits() {
    // scriptcheck doesn't emit decisions for tools it wasn't designed to handle,
    // regardless of permission mode. Claude Code applies its own per-mode default
    // when the hook stays silent.
    let input = hook_json_with_mode(
        "Agent",
        serde_json::json!({}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "expected empty stdout for unknown tool in bypass, got: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[skuld::test]
fn bypass_ls_is_allowed() {
    // After the refactor, bypass mode runs the full pipeline. A scriptcheck-ask
    // command (ls has no matching allow rule in /tmp settings) is converted to
    // allow via apply_permission_mode's Ask→Allow transform.
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "ls"}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_camelcase_key() {
    // Verify the camelCase `permissionMode` alias works for bypass
    let json = serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "unknown-cmd"},
        "permissionMode": "bypassPermissions",
        "tool_use_id": "toolu_test"
    });
    let input = json.to_string().into_bytes();
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn bypass_empty_bash_command_silent_exits() {
    // Empty Bash command is a malformed input scriptcheck wasn't designed for;
    // silent-exit regardless of mode.
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": ""}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "expected empty stdout for empty Bash command, got: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[skuld::test]
fn bypass_missing_tool_input_fields() {
    // Write tool with no file_path — missing-path emits Ask, transform converts to Allow in bypass.
    let input = hook_json_with_mode(
        "Write",
        serde_json::json!({}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
    let reason = parse_reason(&output);
    assert!(
        reason.contains("Missing file path"),
        "bypass should preserve the informative reason via custom_reason, got: {reason}"
    );
}

// ── Permission mode (auto) tests ────────────────────────────────────────────

#[skuld::test]
fn auto_allows_unmatched_bash() {
    // Ask-worthy command in auto mode is transformed to Allow so scriptcheck
    // doesn't add an extra prompt layer above Claude Code's own classifier.
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "my-totally-unknown-cmd --flag"}),
        "/tmp",
        Some("auto"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn auto_respects_deny_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    // Deny rules fire in auto mode — that's the hardening value of keeping
    // scriptcheck as a pre-classifier layer.
    let project_root = dir.to_string_lossy().to_string();
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::write(
        dir.join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Bash(rm *)"]}}"#,
    )
    .unwrap();

    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "rm -rf /tmp/claude-test"}),
        &project_root,
        Some("auto"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

#[skuld::test]
fn auto_preserves_missing_rules_after_transform(#[fixture(temp_dir)] dir: &std::path::Path) {
    // Ask → Allow transform must not drop the missing_rules list from the log.
    let project_root = dir.to_string_lossy().to_string();
    let log_path = dir.join("test-log.yaml");

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "my-totally-unknown-xyzzy"}),
        &project_root,
        Some("auto"),
    );
    let output = Command::new(binary)
        .env("CLAUDE_SCRIPTCHECK_HOOK_HOME", dir)
        .env("CLAUDE_SCRIPTCHECK_LOG_PATH", &log_path)
        .env("CLAUDE_PROJECT_DIR", &project_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(&input)?;
            child.wait_with_output()
        })
        .expect("binary run");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");

    let log = std::fs::read_to_string(&log_path).expect("log file");
    assert!(
        log.contains("xyzzy"),
        "log should record the unmatched rule (contains 'xyzzy'), got:\n{log}"
    );
    assert!(
        log.contains("missing_rules") || log.contains("missing-rules"),
        "log should record missing_rules field, got:\n{log}"
    );
}

#[skuld::test]
fn auto_respects_read_deny_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    let canonical = std::fs::canonicalize(dir).unwrap();
    let project_root = canonical.to_string_lossy().replace('\\', "/");
    let secret_path = format!("{project_root}/secret.txt");
    std::fs::write(&secret_path, "secret").unwrap();
    std::fs::create_dir_all(canonical.join(".claude")).unwrap();
    // `//path` is Claude Code's absolute-path escape; bare `/path` is
    // interpreted as project-root-relative.
    std::fs::write(
        canonical.join(".claude/settings.json"),
        format!(r#"{{"permissions":{{"deny":["Read(/{project_root}/secret.txt)"]}}}}"#),
    )
    .unwrap();

    let input = file_tool_json_with_mode("Read", &secret_path, &project_root, Some("auto"));
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

// ── Permission mode (dontAsk) tests ─────────────────────────────────────────

#[skuld::test]
fn dont_ask_denies_unmatched_bash() {
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "my-totally-unknown-cmd --flag"}),
        "/tmp",
        Some("dontAsk"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
    let reason = parse_reason(&output);
    assert!(
        reason.starts_with("dontAsk mode: command requires rule(s)"),
        "reason should describe dontAsk deny, got: {reason}"
    );
    assert!(
        reason.contains("my-totally-unknown-cmd") || reason.contains("Bash("),
        "reason should name the missing rule, got: {reason}"
    );
}

#[skuld::test]
fn dont_ask_respects_allow_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::write(
        dir.join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(echo *)"]}}"#,
    )
    .unwrap();

    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "echo hello"}),
        &project_root,
        Some("dontAsk"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn dont_ask_respects_deny_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::write(
        dir.join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Bash(rm *)"]}}"#,
    )
    .unwrap();

    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "rm /tmp/nothing"}),
        &project_root,
        Some("dontAsk"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

#[skuld::test]
fn dont_ask_denies_grep_without_rule() {
    let input = hook_json_with_mode(
        "Grep",
        serde_json::json!({"pattern": "x", "path": "/etc"}),
        "/tmp",
        Some("dontAsk"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

#[skuld::test]
fn missing_file_path_in_dont_ask_denies() {
    let input = hook_json_with_mode("Write", serde_json::json!({}), "/tmp", Some("dontAsk"));
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

// ── Permission mode (bypass) deny-respecting regression tests ───────────────

#[skuld::test]
fn bypass_respects_bash_deny_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    // Behavior change: bypass used to unconditionally allow; now deny rules fire.
    let project_root = dir.to_string_lossy().to_string();
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::write(
        dir.join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Bash(rm *)"]}}"#,
    )
    .unwrap();

    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "rm -rf /tmp/claude-test"}),
        &project_root,
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

#[skuld::test]
fn bypass_respects_file_deny_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    let canonical = std::fs::canonicalize(dir).unwrap();
    let project_root = canonical.to_string_lossy().replace('\\', "/");
    let forbidden_path = format!("{project_root}/forbidden.txt");
    std::fs::create_dir_all(canonical.join(".claude")).unwrap();
    // `//path` is Claude Code's absolute-path escape.
    std::fs::write(
        canonical.join(".claude/settings.json"),
        format!(r#"{{"permissions":{{"deny":["Write(/{project_root}/forbidden.txt)"]}}}}"#,),
    )
    .unwrap();

    let input = file_tool_json_with_mode(
        "Write",
        &forbidden_path,
        &project_root,
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

#[skuld::test]
fn bypass_respects_monitor_deny_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    // Monitor is a transparent Bash wrapper — deny rules must fire the same way.
    let project_root = dir.to_string_lossy().to_string();
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::write(
        dir.join(".claude/settings.json"),
        r#"{"permissions":{"deny":["Bash(rm *)"]}}"#,
    )
    .unwrap();

    let input = hook_json_with_mode(
        "Monitor",
        serde_json::json!({
            "command": "rm -rf /tmp/claude-test",
            "description": "test",
            "persistent": false,
            "timeout_ms": 1000
        }),
        &project_root,
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
}

// ── Parse failure transform tests ───────────────────────────────────────────

#[skuld::test]
fn bash_parse_failure_in_bypass_allows() {
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "if then fi else"}),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
    let reason = parse_reason(&output);
    assert!(
        reason.to_lowercase().contains("parse"),
        "custom_reason should preserve parse-failure text even after transform, got: {reason}"
    );
}

#[skuld::test]
fn bash_parse_failure_in_auto_allows() {
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "if then fi else"}),
        "/tmp",
        Some("auto"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
    let reason = parse_reason(&output);
    assert!(
        reason.to_lowercase().contains("parse"),
        "auto should preserve parse-failure reason via custom_reason, got: {reason}"
    );
}

#[skuld::test]
fn bash_parse_failure_in_dont_ask_denies() {
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "if then fi else"}),
        "/tmp",
        Some("dontAsk"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");
    let reason = parse_reason(&output);
    // custom_reason (parse-failure context) is prefixed in the Deny reason so
    // the user sees both WHY the command was ambiguous AND the dontAsk explanation.
    assert!(
        reason.to_lowercase().contains("parse"),
        "dontAsk should prefix parse-failure context onto the deny reason, got: {reason}"
    );
    assert!(
        reason.contains("dontAsk mode"),
        "dontAsk should still include the mode explanation, got: {reason}"
    );
}

#[skuld::test]
fn dont_ask_full_reason_format() {
    // Pin the exact reason wording so accidental drift is caught.
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "my-unknown-xyz"}),
        "/tmp",
        Some("dontAsk"),
    );
    let output = run_binary_with_env(&input, &[]);
    assert_eq!(parse_decision(&output), "deny");
    let reason = parse_reason(&output);
    assert!(
        reason.starts_with("dontAsk mode: command requires rule(s) not in settings:"),
        "reason prefix should match, got: {reason}"
    );
    assert!(
        reason.ends_with("Add the listed rule(s) to permissions.allow to run this."),
        "reason suffix should guide the user to the fix, got: {reason}"
    );
    assert!(
        reason.contains("Bash(my-unknown-xyz)"),
        "reason should list the missing rule, got: {reason}"
    );
}

#[skuld::test]
fn dont_ask_preserves_missing_rules_in_log(#[fixture(temp_dir)] dir: &std::path::Path) {
    // Regression guard: Ask → Deny transform under dontAsk must keep the
    // structured missing_rules list in the YAML log (not just in the reason text).
    let project_root = dir.to_string_lossy().to_string();
    let log_path = dir.join("test-log.yaml");

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "unique-dontask-marker-abc"}),
        &project_root,
        Some("dontAsk"),
    );
    let output = Command::new(binary)
        .env("CLAUDE_SCRIPTCHECK_HOOK_HOME", dir)
        .env("CLAUDE_SCRIPTCHECK_LOG_PATH", &log_path)
        .env("CLAUDE_PROJECT_DIR", &project_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(&input)?;
            child.wait_with_output()
        })
        .expect("binary run");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "deny");

    let log = std::fs::read_to_string(&log_path).expect("log file");
    assert!(
        log.contains("missing_rules"),
        "log should record missing_rules field for dontAsk Deny, got:\n{log}"
    );
    assert!(
        log.contains("Bash(unique-dontask-marker-abc)"),
        "log should list the unmatched rule, got:\n{log}"
    );
}

#[skuld::test]
fn cli_check_parse_failure_bypass_allows() {
    // Match the hook path for unparseable input.
    let output = run_check_cli(&[
        "if then fi else",
        "--cwd",
        "/tmp",
        "--permission-mode",
        "bypassPermissions",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("ALLOW"),
        "expected ALLOW for bypass + parse failure, got: {stdout}",
    );
    assert!(
        stdout.to_lowercase().contains("parse"),
        "custom_reason should surface the parse-failure text, got: {stdout}",
    );
}

#[skuld::test]
fn cli_check_parse_failure_dont_ask_denies() {
    let output = run_check_cli(&[
        "if then fi else",
        "--cwd",
        "/tmp",
        "--permission-mode",
        "dontAsk",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "deny exits nonzero; stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("DENY"),
        "expected DENY for dontAsk + parse failure, got: {stdout}",
    );
}

// ── plan and unknown mode passthrough ───────────────────────────────────────

#[skuld::test]
fn plan_mode_behaves_as_default() {
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "my-totally-unknown-cmd"}),
        "/tmp",
        Some("plan"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "ask");
}

#[skuld::test]
fn unknown_permission_mode_behaves_as_default() {
    // Forward-compat: an unknown mode string falls back to default behavior
    // (PermissionMode::from_hook_str returns None for unrecognized inputs).
    let input = hook_json_with_mode(
        "Bash",
        serde_json::json!({"command": "my-totally-unknown-cmd"}),
        "/tmp",
        Some("futureMode"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "ask");
}

// ── Monitor tool tests ──────────────────────────────────────────────────────

/// Build a JSON payload that mirrors the real Monitor tool_input schema
/// (`command`, `description`, `persistent`, `timeout_ms`).
fn monitor_hook_json(command: &str, persistent: bool, timeout_ms: u64) -> Vec<u8> {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Monitor",
        "tool_input": {
            "command": command,
            "description": "test monitor",
            "persistent": persistent,
            "timeout_ms": timeout_ms
        },
        "tool_use_id": "toolu_test"
    })
    .to_string()
    .into_bytes()
}

#[skuld::test]
fn monitor_dispatched_to_bash_handler() {
    // Parity contract: Monitor and Bash with the same command produce identical decisions.
    let cmd = "ls -la /tmp";
    let bash_out = run_binary(&hook_json("Bash", cmd));
    let monitor_out = run_binary(&hook_json("Monitor", cmd));

    assert_eq!(bash_out.status.code(), Some(0));
    assert_eq!(monitor_out.status.code(), Some(0));
    assert_eq!(
        parse_decision(&bash_out),
        parse_decision(&monitor_out),
        "Monitor and Bash with the same command must produce the same decision"
    );
}

#[skuld::test]
fn monitor_unknown_command_asks() {
    let output = run_binary(&hook_json("Monitor", "my-totally-unknown-command --flag"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "ask");
}

#[skuld::test]
fn monitor_full_schema_tolerated() {
    // Full schema with all four required fields (command, description, persistent, timeout_ms).
    // Unknown command → deterministic `ask` regardless of host settings.
    let output = run_binary(&monitor_hook_json(
        "my-totally-unknown-command --flag",
        true,
        600_000,
    ));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "ask");
}

#[skuld::test]
fn monitor_unparseable_shell_asks() {
    let output = run_binary(&hook_json("Monitor", "if then fi else"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "ask");
    let reason = parse_reason(&output);
    assert!(
        reason.to_lowercase().contains("parse"),
        "reason should mention parse failure, got: {reason}"
    );
}

#[skuld::test]
fn monitor_empty_command_exits_cleanly() {
    let output = run_binary(&hook_json("Monitor", ""));
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[skuld::test]
fn monitor_missing_command_field_exits_cleanly() {
    let input = serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Monitor",
        "tool_input": {},
        "tool_use_id": "toolu_test"
    })
    .to_string()
    .into_bytes();
    let output = run_binary(&input);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[skuld::test]
fn bypass_allows_monitor() {
    let input = hook_json_with_mode(
        "Monitor",
        serde_json::json!({
            "command": "unknown-cmd --flag",
            "description": "x",
            "persistent": false,
            "timeout_ms": 300000
        }),
        "/tmp",
        Some("bypassPermissions"),
    );
    let output = run_binary_with_env(&input, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_decision(&output), "allow");
}

#[skuld::test]
fn accept_edits_allows_monitor_workspace_write(#[fixture(temp_dir)] dir: &std::path::Path) {
    let project_root = dir.to_string_lossy().to_string();
    // Normalize to forward slashes AND single-quote the path. Windows temp-dir
    // paths contain backslashes (bash escape character) and may contain spaces
    // (word-splitting) — single quotes disable both.
    let file_in_workspace = format!("{}/output.txt", project_root.replace('\\', "/"));

    let input = hook_json_with_mode(
        "Monitor",
        serde_json::json!({
            "command": format!("touch '{file_in_workspace}'"),
            "description": "x",
            "persistent": false,
            "timeout_ms": 300000
        }),
        &project_root,
        Some("acceptEdits"),
    );
    let output = run_binary_with_env(&input, &[("CLAUDE_PROJECT_DIR", &project_root)]);

    assert_eq!(output.status.code(), Some(0));
    let decision = parse_decision(&output);
    assert_eq!(
        decision, "allow",
        "acceptEdits + Monitor workspace write should auto-allow"
    );
}

// ── CLI dry-run (--permission-mode) tests ───────────────────────────────────

fn run_check_cli(args: &[&str]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let mut cmd = Command::new(binary);
    let _log_guard = apply_test_isolation(&mut cmd);
    cmd.arg("check");
    cmd.args(args);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("cli run")
}

#[skuld::test]
fn cli_check_auto_allows_unmatched() {
    let output = run_check_cli(&[
        "my-totally-unknown-cli-cmd",
        "--cwd",
        "/tmp",
        "--permission-mode",
        "auto",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("ALLOW"),
        "expected ALLOW for auto mode, got: {stdout}",
    );
}

#[skuld::test]
fn cli_check_dont_ask_denies_unmatched() {
    let output = run_check_cli(&[
        "my-totally-unknown-cli-cmd",
        "--cwd",
        "/tmp",
        "--permission-mode",
        "dontAsk",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "deny exits nonzero; stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("DENY"),
        "expected DENY for dontAsk mode, got: {stdout}",
    );
}

#[skuld::test]
fn cli_check_default_mode_asks_unmatched() {
    let output = run_check_cli(&["my-totally-unknown-cli-cmd", "--cwd", "/tmp"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("ASK"),
        "expected ASK for default mode, got: {stdout}",
    );
}

#[skuld::test]
fn cli_check_rejects_invalid_mode() {
    // clap's ValueEnum rejects values that don't match the enum.
    let output = run_check_cli(&[
        "my-totally-unknown-cli-cmd",
        "--cwd",
        "/tmp",
        "--permission-mode",
        "not-a-real-mode",
    ]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "clap should reject unknown --permission-mode values; got stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
