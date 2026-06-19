# Dual-Agent Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Codex support without changing the substance of command evaluation, by keeping the current checker authoritative and wrapping it in explicit Claude and Codex adapters.

**Architecture:** Preserve `checker::CheckResult` as the only shared decision model. Keep Claude settings discovery in `settings.rs`, add a Codex config loader that mirrors Codex’s own config-layer order, and add thin adapters that translate hook stdin and stdout plus install or uninstall behavior per agent. Use `toml_edit` for Codex config mutation so unrelated TOML and hook entries survive, while stale scriptcheck hook state is cleaned up.

**Tech Stack:** Rust 2021, `clap`, `serde`, `serde_json`, `toml_edit`, `thaum`, `skuld`

______________________________________________________________________

## File Structure

- Create: `src/args.rs`
  - Shared clap parsing types so CLI parsing can be tested in the library.
- Create: `src/agent.rs`
  - Shared `Agent` enum, normalized hook request type, and adapter-facing helpers that operate on `CheckResult`.
- Create: `src/agent/claude.rs`
  - Claude hook input/output transport plus Claude install or uninstall helpers.
- Create: `src/agent/codex.rs`
  - Codex `PreToolUse` transport plus Codex install or uninstall helpers.
- Create: `src/codex_settings.rs`
  - Codex config-layer discovery, TOML rule loading, and TOML mutation helpers.
- Modify: `src/settings.rs`
  - Keep Claude settings discovery and shared permission/path-resolution helpers.
- Modify: `src/permission.rs`
  - Add a `load_perms_from_settings` path so adapters can supply preloaded settings instead of hard-wiring Claude loading.
- Modify: `src/cli.rs`
  - Route `install`, `uninstall`, and `check` through the selected agent.
- Modify: `src/main.rs`
  - Use `args.rs`, require top-level `--agent` only for hook mode, and dispatch to the selected adapter.
- Modify: `src/lib.rs`
  - Export new modules.
- Modify: `src/hook.rs`
  - Keep only common Claude transport helpers or compatibility helpers that remain useful after adapter extraction.
- Modify: `Cargo.toml`
  - Add `toml_edit`.
- Create: `tests/suite/agent.rs`
  - Adapter transport tests for Claude and Codex.
- Modify: `tests/suite/cli.rs`
  - Agent-aware install or uninstall tests, legacy migration tests, and path-form matching tests.
- Modify: `tests/suite/settings.rs`
  - Codex config-layer and precedence tests.
- Modify: `tests/suite/integration.rs`
  - Binary hook I/O tests updated for explicit runtime `--agent`.
- Modify: `tests/suite.rs`
  - Register the new suite module.
- Create: `tests/fixtures/codex_pre_tool_use_bash.json`
  - Minimal checked-in Codex `PreToolUse` Bash payload fixture taken from the local probe.
- Create: `tests/fixtures/codex_pre_tool_use_apply_patch.json`
  - Minimal checked-in Codex `PreToolUse` apply_patch payload fixture.
- Modify: `README.md`
  - Update public CLI usage.
- Modify: `CLAUDE.md`
  - Update source map and architecture notes.

## Fixed Decisions

- Hook runtime stays explicit: `claude-scriptcheck --agent claude` and `claude-scriptcheck --agent codex`.
- Install-family commands stay positional, per approved design: `claude-scriptcheck install claude`, `claude-scriptcheck install codex`.
- `check` also uses a positional agent selector to avoid conflicting selectors: `claude-scriptcheck check claude "git status"` and `claude-scriptcheck check codex "git status"`.
- Top-level `--agent` is invalid when any subcommand is present.
- Codex support is `PreToolUse` only in v1.
- Codex decision mapping is:
  - `Allow -> allow`
  - `Deny -> deny`
  - `Ask -> no stdout`
- Codex install surface in v1 is the documented native interception surface only:
  - `Bash`
  - `apply_patch`
  - matcher aliases `Edit` and `Write`

## Codex Config Mirroring

Codex-backed rule loading must mirror Codex’s own config-layer order and trust model.

- User config path: `~/.codex/config.toml`
- Project config path: `.codex/config.toml`
- Project layers are discovered from the project root down to the current working directory, with the closest layer winning.
- Project layers only participate when the project is trusted.

The implementation plan therefore assumes:

- `codex_settings.rs` discovers the Codex config chain from current working directory ancestry.
- Rule merging follows that same layer order.
- Scriptcheck-specific precedence inside the merged Codex-backed rules remains the checker’s existing semantics, but path and layer preference must follow Codex’s own config resolution.
- No separate invented search path is allowed for Codex-backed rules.

## Task 1: Make the CLI single-selector and testable

**Files:**

- Create: `src/args.rs`

- Modify: `src/lib.rs`

- Modify: `src/main.rs`

- Modify: `tests/suite/cli.rs`

- Test: `src/args.rs`

- [ ] **Step 1: Write the failing parsing tests**

```rust
// src/args.rs
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn install_accepts_positional_agent() {
        let cli = Cli::try_parse_from(["claude-scriptcheck", "install", "codex"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Install {
                agent: Agent::Codex,
                project: false
            })
        ));
    }

    #[test]
    fn check_accepts_positional_agent() {
        let cli = Cli::try_parse_from(["claude-scriptcheck", "check", "claude", "ls"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Check {
                agent: Agent::Claude,
                command,
                ..
            }) if command == "ls"
        ));
    }

    #[test]
    fn top_level_agent_rejected_with_subcommand() {
        let result =
            Cli::try_parse_from(["claude-scriptcheck", "--agent", "claude", "install", "codex"]);
        assert!(result.is_err());
    }
}
```

```rust
// tests/suite/cli.rs
#[skuld::test]
fn binary_without_args_fails_before_hook_dispatch() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = std::process::Command::new(binary).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--agent"));
}
```

- [ ] **Step 2: Run the parsing tests and verify they fail**

Run: `cargo test args::tests::install_accepts_positional_agent`
Expected: FAIL because `Cli` is still private to `src/main.rs`

Run: `cargo test --test suite`
Expected: FAIL because no-arg binary execution still enters hook mode

- [ ] **Step 3: Extract clap parsing to `src/args.rs`**

```rust
// src/args.rs
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    Claude,
    Codex,
}

#[derive(Parser)]
#[command(name = "claude-scriptcheck", about = "Permission checker for Claude Code and Codex hooks")]
pub struct Cli {
    #[arg(long, value_enum)]
    pub agent: Option<Agent>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Install { agent: Agent, #[arg(long)] project: bool },
    Uninstall { agent: Agent, #[arg(long)] project: bool },
    Check {
        agent: Agent,
        command: String,
        #[arg(long, default_value = ".")]
        cwd: String,
        #[arg(long, value_enum)]
        permission_mode: Option<crate::permission_mode::PermissionMode>,
    },
    Log { /* existing flags unchanged */ },
    LogPath,
    Upgrade,
}
```

- [ ] **Step 4: Re-run the parsing tests and verify they pass**

Run: `cargo test args::tests::`
Expected: PASS

Run: `cargo test --test suite`
Expected: FAIL only on still-unimplemented runtime and install behavior

- [ ] **Step 5: Commit the parsing extraction**

```bash
git add src/args.rs src/lib.rs src/main.rs tests/suite/cli.rs
git commit -m "Extract single-selector CLI parsing"
```

## Task 2: Add Codex settings loading without destabilizing Claude settings

**Files:**

- Create: `src/codex_settings.rs`

- Modify: `src/settings.rs`

- Modify: `src/permission.rs`

- Modify: `tests/suite/settings.rs`

- [ ] **Step 1: Write the failing settings-source tests**

```rust
use claude_scriptcheck::codex_settings::{
    codex_config_chain_from_paths,
    load_codex_settings_from_contents,
};
use claude_scriptcheck::settings::Permissions;

#[skuld::test]
fn codex_config_chain_orders_root_to_cwd() {
    let chain = codex_config_chain_from_paths(
        "/repo/apps/service",
        &[
            "/repo/.codex/config.toml",
            "/repo/apps/.codex/config.toml",
            "/repo/apps/service/.codex/config.toml",
        ],
    );

    assert_eq!(
        chain,
        vec![
            "/repo/.codex/config.toml",
            "/repo/apps/.codex/config.toml",
            "/repo/apps/service/.codex/config.toml"
        ]
    );
}

#[skuld::test]
fn codex_user_and_project_rules_merge() {
    let loaded = load_codex_settings_from_contents(
        Some(
            r#"
            [scriptcheck.permissions]
            allow = ["Bash(ls *)"]
            additional_directories = ["/workspace"]
            "#,
        ),
        Some(
            r#"
            [scriptcheck.permissions]
            deny = ["Bash(rm *)"]
            ask = ["Write(/tmp/**)"]
            "#,
        ),
    )
    .unwrap();

    assert_eq!(loaded.permissions.allow, vec!["Bash(ls *)"]);
    assert_eq!(loaded.permissions.deny, vec!["Bash(rm *)"]);
    assert_eq!(loaded.permissions.ask, vec!["Write(/tmp/**)"]);
    assert_eq!(loaded.permissions.additional_directories, vec!["/workspace"]);
}

#[skuld::test]
fn load_perms_from_settings_respects_accept_edits() {
    let mut permissions = Permissions::default();
    permissions.additional_directories.push("/workspace".into());
    let loaded = claude_scriptcheck::settings::LoadedSettings { permissions };

    let parsed = claude_scriptcheck::permission::load_perms_from_settings(
        &loaded,
        "/repo",
        "/repo",
        Some(claude_scriptcheck::permission_mode::PermissionMode::AcceptEdits),
    );

    assert!(parsed.write.allow.iter().any(|rule| rule.pattern().contains("/workspace/")));
}
```

- [ ] **Step 2: Run the settings tests and verify they fail**

Run: `cargo test --test suite`
Expected: FAIL because `codex_settings` and `load_perms_from_settings` do not exist

- [ ] **Step 3: Implement Codex loader plus `load_perms_from_settings`**

```rust
// src/codex_settings.rs
use crate::settings::{LoadedSettings, Permissions};

pub fn load_codex_settings_from_contents(
    user: Option<&str>,
    project: Option<&str>,
) -> Result<LoadedSettings, String> {
    let mut permissions = Permissions::default();
    merge_scriptcheck_permissions(user, &mut permissions)?;
    merge_scriptcheck_permissions(project, &mut permissions)?;
    Ok(LoadedSettings { permissions })
}
```

```rust
// src/permission.rs
pub fn load_perms_from_settings(
    loaded: &LoadedSettings,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) -> ParsedPermissions {
    let mut parsed = parse_rules(&loaded.permissions, cwd, project_root);
    if permission_mode == Some(PermissionMode::AcceptEdits) {
        let workspace_dirs = workspace_dirs_from_loaded_settings(loaded, project_root);
        inject_accept_edits_rules(&mut parsed, &workspace_dirs);
    }
    parsed
}
```

- [ ] **Step 4: Re-run the settings tests and verify they pass**

Run: `cargo test --test suite`
Expected: PASS for new Codex settings coverage and existing Claude settings coverage

- [ ] **Step 5: Commit the settings work**

```bash
git add src/codex_settings.rs src/settings.rs src/permission.rs tests/suite/settings.rs src/lib.rs
git commit -m "Add Codex config loading path"
```

## Task 3: Add adapters that consume and render `CheckResult`

**Files:**

- Create: `src/agent.rs`

- Create: `src/agent/claude.rs`

- Create: `src/agent/codex.rs`

- Modify: `src/hook.rs`

- Create: `tests/suite/agent.rs`

- Modify: `tests/suite.rs`

- Create: `tests/fixtures/codex_pre_tool_use_bash.json`

- Create: `tests/fixtures/codex_pre_tool_use_apply_patch.json`

- [ ] **Step 1: Write the failing adapter tests**

```rust
use claude_scriptcheck::agent::claude::{parse_claude_hook_input, render_claude_output};
use claude_scriptcheck::agent::codex::{parse_codex_hook_input, render_codex_output};
use claude_scriptcheck::checker::{CheckResult, Decision};

#[skuld::test]
fn claude_allow_renders_allow() {
    let result = CheckResult {
        decision: Decision::Allow,
        matched_allow: vec![],
        matched_deny: vec![],
        missing_rules: vec![],
        custom_reason: Some("allowed".into()),
    };
    let json = render_claude_output(&result).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[skuld::test]
fn claude_deny_renders_deny() {
    let result = CheckResult {
        decision: Decision::Deny("blocked".into()),
        matched_allow: vec![],
        matched_deny: vec![],
        missing_rules: vec![],
        custom_reason: None,
    };
    let json = render_claude_output(&result).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[skuld::test]
fn claude_ask_preserves_reason() {
    let result = CheckResult {
        decision: Decision::Ask,
        matched_allow: vec![],
        matched_deny: vec![],
        missing_rules: vec!["Bash(rm *)".into()],
        custom_reason: Some("Missing permission rules: Bash(rm *)".into()),
    };
    let json = render_claude_output(&result).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[skuld::test]
fn codex_allow_renders_allow() {
    let result = CheckResult {
        decision: Decision::Allow,
        matched_allow: vec![],
        matched_deny: vec![],
        missing_rules: vec![],
        custom_reason: Some("allowed".into()),
    };
    let json = render_codex_output(&result).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[skuld::test]
fn codex_deny_renders_deny() {
    let result = CheckResult {
        decision: Decision::Deny("blocked".into()),
        matched_allow: vec![],
        matched_deny: vec![],
        missing_rules: vec![],
        custom_reason: None,
    };
    let json = render_codex_output(&result).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[skuld::test]
fn codex_ask_renders_no_stdout() {
    let result = CheckResult {
        decision: Decision::Ask,
        matched_allow: vec![],
        matched_deny: vec![],
        missing_rules: vec!["Bash(git push *)".into()],
        custom_reason: Some("Missing permission rules: Bash(git push *)".into()),
    };
    assert!(render_codex_output(&result).is_none());
}
```

- [ ] **Step 2: Run the adapter tests and verify they fail**

Run: `cargo test --test suite`
Expected: FAIL because adapter modules and checked-in Codex fixtures do not exist

- [ ] **Step 3: Implement adapter parsing and rendering**

```rust
// src/agent.rs
use crate::checker::CheckResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHookRequest {
    pub session_id: String,
    pub cwd: String,
    pub tool_name: String,
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub path: Option<String>,
    pub permission_mode: Option<String>,
}

pub trait HookAdapter {
    fn parse_input(input: &str) -> Result<NormalizedHookRequest, String>;
    fn render_output(result: &CheckResult) -> Option<serde_json::Value>;
}
```

```rust
// src/agent/codex.rs
pub fn render_codex_output(result: &CheckResult) -> Option<serde_json::Value> {
    match &result.decision {
        Decision::Allow => Some(make_hook_output("allow", allow_reason(result))),
        Decision::Deny(reason) => Some(make_hook_output("deny", reason)),
        Decision::Ask => None,
    }
}
```

- [ ] **Step 4: Re-run the adapter tests and verify they pass**

Run: `cargo test --test suite`
Expected: PASS for adapter mappings and fixture parsing

- [ ] **Step 5: Commit the adapter layer**

```bash
git add src/agent.rs src/agent/claude.rs src/agent/codex.rs src/hook.rs tests/suite/agent.rs tests/suite.rs tests/fixtures/codex_pre_tool_use_bash.json tests/fixtures/codex_pre_tool_use_apply_patch.json src/lib.rs
git commit -m "Add Claude and Codex adapters"
```

## Task 4: Route hook execution and dry-run checks through the selected agent

**Files:**

- Modify: `src/main.rs`

- Modify: `src/cli.rs`

- Modify: `tests/suite/integration.rs`

- Modify: `tests/suite/cli.rs`

- [ ] **Step 1: Write the failing runtime tests**

```rust
// tests/suite/integration.rs
#[skuld::test]
fn claude_hook_requires_runtime_agent_flag() {
    let output = run_binary_with_args(&[], &hook_json("Bash", "ls"));
    assert_eq!(output.status.code(), Some(2));
}

#[skuld::test]
fn claude_hook_with_agent_flag_produces_claude_json() {
    let output = run_binary_with_args(&["--agent", "claude"], &hook_json("Bash", "ls"));
    assert_eq!(output.status.code(), Some(0));
    parse_decision(&output);
}

#[skuld::test]
fn codex_hook_ask_produces_no_stdout() {
    let output =
        run_binary_with_args(&["--agent", "codex"], &hook_json("Bash", "unknown-command"));
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}
```

```rust
// tests/suite/cli.rs
#[skuld::test]
fn check_uses_positional_agent_selector() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = std::process::Command::new(binary)
        .args(["check", "codex", "ls"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALLOW") || stdout.contains("ASK") || stdout.contains("DENY"));
}

#[skuld::test]
fn check_rejects_top_level_agent_flag() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = std::process::Command::new(binary)
        .args(["--agent", "claude", "check", "codex", "ls"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
}
```

- [ ] **Step 2: Run the runtime tests and verify they fail**

Run: `cargo test --test suite`
Expected: FAIL because runtime still defaults to Claude hook mode and `check` is still Claude-only

- [ ] **Step 3: Dispatch hook evaluation and `check` through the selected agent**

```rust
// src/main.rs
fn run_hook(agent: Agent) {
    let input = read_stdin_json();
    match agent {
        Agent::Claude => crate::agent::claude::run_hook(&input),
        Agent::Codex => crate::agent::codex::run_hook(&input),
    }
}
```

```rust
// src/cli.rs
pub fn check(agent: Agent, command: &str, cwd: &str, permission_mode: Option<PermissionMode>) {
    let loaded = match agent {
        Agent::Claude => crate::settings::load_settings(&resolved_cwd, &project_root),
        Agent::Codex => crate::codex_settings::load_codex_settings(&resolved_cwd, &project_root),
    };
    let parsed =
        permission::load_perms_from_settings(&loaded, &resolved_cwd, &project_root, permission_mode);
    // existing checker path stays the same after this point
}
```

- [ ] **Step 4: Re-run the runtime tests and verify they pass**

Run: `cargo test --test suite`
Expected: PASS for runtime agent selection and Codex no-stdout Ask behavior

- [ ] **Step 5: Commit the runtime routing**

```bash
git add src/main.rs src/cli.rs tests/suite/integration.rs tests/suite/cli.rs
git commit -m "Route runtime by explicit agent"
```

## Task 5: Implement migration-safe install and uninstall for Claude and Codex

**Files:**

- Modify: `src/agent/claude.rs`

- Modify: `src/agent/codex.rs`

- Modify: `src/codex_settings.rs`

- Modify: `src/cli.rs`

- Modify: `tests/suite/cli.rs`

- [ ] **Step 1: Write the failing install and uninstall tests**

```rust
#[skuld::test]
fn claude_install_rewrites_legacy_unflagged_entries() {
    let settings = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
            }]
        }
    });

    let rewritten =
        claude_scriptcheck::agent::claude::rewrite_install_entries(settings, "claude-scriptcheck --agent claude");

    let command = rewritten["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert_eq!(command, "claude-scriptcheck --agent claude");
}

#[skuld::test]
fn install_matching_is_path_form_tolerant_but_agent_specific() {
    assert!(claude_scriptcheck::agent::claude::command_matches_agent_install(
        "/usr/local/bin/claude-scriptcheck --agent claude",
        "claude-scriptcheck",
        claude_scriptcheck::agent::Agent::Claude,
    ));
    assert!(!claude_scriptcheck::agent::claude::command_matches_agent_install(
        "claude-scriptcheck --agent codex",
        "claude-scriptcheck",
        claude_scriptcheck::agent::Agent::Claude,
    ));
}

#[skuld::test]
fn codex_install_preserves_unrelated_hooks_and_rewrites_legacy_scriptcheck_entries() {
    let updated = claude_scriptcheck::codex_settings::install_codex_hooks_into_toml(
        r#"
        [features]
        hooks = false

        [[hooks.PreToolUse]]
        matcher = "^Bash$"

        [[hooks.PreToolUse.hooks]]
        type = "command"
        command = "claude-scriptcheck"

        [[hooks.PreToolUse]]
        matcher = "^Other$"

        [[hooks.PreToolUse.hooks]]
        type = "command"
        command = "other-tool"

        [hooks.state."/Users/test/.codex/config.toml:pre_tool_use:0:0"]
        trusted_hash = "sha256:abc"
        "#,
        "claude-scriptcheck --agent codex",
    )
    .unwrap();

    assert!(updated.contains("hooks = true"));
    assert!(updated.contains("other-tool"));
    assert!(updated.contains("claude-scriptcheck --agent codex"));
    assert!(!updated.contains("command = \"claude-scriptcheck\""));
    assert!(!updated.contains("sha256:abc"));
}
```

- [ ] **Step 2: Run the install tests and verify they fail**

Run: `cargo test --test suite`
Expected: FAIL because install logic still uses coarse marker matching and Codex TOML rewriting does not exist

- [ ] **Step 3: Implement migration-safe install helpers**

```rust
// src/agent/claude.rs
pub fn install_command(binary_path: &str) -> String {
    format!("{binary_path} --agent claude")
}

pub fn command_matches_agent_install(cmd: &str, binary_path: &str, agent: Agent) -> bool {
    let marker = "claude-scriptcheck";
    let agent_flag = match agent {
        Agent::Claude => "--agent claude",
        Agent::Codex => "--agent codex",
    };
    (cmd == format!("{binary_path} {agent_flag}") || cmd.contains(marker))
        && cmd.contains(agent_flag)
}
```

```rust
// src/codex_settings.rs
pub fn install_codex_hooks_into_toml(input: &str, command: &str) -> Result<String, String> {
    let mut doc = input.parse::<toml_edit::DocumentMut>().map_err(|e| e.to_string())?;
    ensure_hooks_enabled(&mut doc);
    remove_legacy_scriptcheck_pre_tool_use_entries(&mut doc);
    ensure_pre_tool_use_hook(&mut doc, "^Bash$", command)?;
    ensure_pre_tool_use_hook(&mut doc, "^apply_patch$", command)?;
    ensure_pre_tool_use_hook(&mut doc, "^Edit$", command)?;
    ensure_pre_tool_use_hook(&mut doc, "^Write$", command)?;
    clear_stale_scriptcheck_hook_state(&mut doc);
    Ok(doc.to_string())
}
```

- [ ] **Step 4: Re-run the install and uninstall tests and verify they pass**

Run: `cargo test --test suite`
Expected: PASS for Claude legacy migration, Codex TOML preservation, and stale state cleanup

- [ ] **Step 5: Commit the install and uninstall work**

```bash
git add src/agent/claude.rs src/agent/codex.rs src/codex_settings.rs src/cli.rs tests/suite/cli.rs
git commit -m "Add migration-safe install paths"
```

## Task 6: Verify end-to-end behavior, update docs, and run mandatory reviews

**Files:**

- Modify: `README.md`

- Modify: `CLAUDE.md`

- [ ] **Step 1: Write the documentation checklist**

```markdown
- README must show:
  - `claude-scriptcheck install claude`
  - `claude-scriptcheck install codex`
  - `claude-scriptcheck check claude "git status"`
  - `claude-scriptcheck check codex "git status"`
  - `claude-scriptcheck --agent claude`
  - `claude-scriptcheck --agent codex`
- README must state that runtime hook mode uses top-level `--agent`, while subcommands use a positional agent.
- README must document the Codex v1 hook surface: `Bash`, `apply_patch`, `Edit`, `Write`.
- CLAUDE.md source map must mention `src/args.rs`, `src/agent.rs`, `src/agent/claude.rs`, `src/agent/codex.rs`, and `src/codex_settings.rs`.
```

- [ ] **Step 2: Run the full verification suite**

Run: `cargo test`
Expected: PASS

Run: `cargo build`
Expected: PASS

- [ ] **Step 3: Update the docs**

````markdown
## Build & test

```sh
cargo test
claude-scriptcheck install claude
claude-scriptcheck install codex
claude-scriptcheck check claude "git status"
claude-scriptcheck check codex "git status"
````

````

- [ ] **Step 4: Run mandatory implementation review**

```text
1. Ask the `review` subagent to review the completed implementation.
2. Call `mcp__mcp_codex.codex_implementation_review`.
3. Fix every confirmed issue before claiming completion.
````

- [ ] **Step 5: Commit the docs update**

```bash
git add README.md CLAUDE.md
git commit -m "Document dual-agent support"
```

## Self-Review

- Spec coverage:
  - explicit runtime `--agent`: covered in Tasks 1 and 4
  - install family with positional agent: covered in Tasks 1 and 5
  - shared engine remains authoritative: covered in Tasks 2 and 3 through `CheckResult`
  - Claude semantics preserved: covered in Task 3 and verified in Task 4
  - Codex `PreToolUse` only: covered in Tasks 3, 4, and 5
  - Codex `Allow -> allow`, `Ask -> no stdout`: covered in Tasks 3 and 4
  - Codex config layering mirrored from Codex load order: covered in Task 2
  - legacy Claude and Codex install migration: covered in Task 5
- Placeholder scan:
  - No `TODO`, `TBD`, or deferred follow-up language remains.
- Type consistency:
  - Shared runtime types are `Agent`, `NormalizedHookRequest`, and `CheckResult` throughout the plan.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-17-dual-agent-hook-implementation.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
