use claude_scriptcheck::cli::{
    is_installed_for, parse_install_source, InstallSource, SUPPORTED_MATCHERS,
};

#[skuld::test]
fn detect_git_source() {
    let json = serde_json::json!({
        "installs": {
            "claude-scriptcheck 0.1.0 (git+https://github.com/bindreams/claude-scriptcheck.git#abc123def)": {
                "bins": ["claude-scriptcheck"]
            }
        }
    });
    assert_eq!(
        parse_install_source(&json, "claude-scriptcheck"),
        Some(InstallSource::Git(
            "https://github.com/bindreams/claude-scriptcheck.git".into()
        ))
    );
}

#[skuld::test]
fn detect_registry_source() {
    let json = serde_json::json!({
        "installs": {
            "claude-scriptcheck 0.2.0 (registry+https://github.com/rust-lang/crates.io-index)": {
                "bins": ["claude-scriptcheck"]
            }
        }
    });
    assert_eq!(
        parse_install_source(&json, "claude-scriptcheck"),
        Some(InstallSource::Registry)
    );
}

#[skuld::test]
fn detect_path_source() {
    let json = serde_json::json!({
        "installs": {
            "claude-scriptcheck 0.1.0 (path+file:///home/user/src/claude-scriptcheck)": {
                "bins": ["claude-scriptcheck"]
            }
        }
    });
    assert_eq!(
        parse_install_source(&json, "claude-scriptcheck"),
        Some(InstallSource::Path(
            "/home/user/src/claude-scriptcheck".into()
        ))
    );
}

#[skuld::test]
fn detect_missing_crate() {
    let json = serde_json::json!({
        "installs": {
            "some-other-crate 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)": {
                "bins": ["other"]
            }
        }
    });
    assert_eq!(parse_install_source(&json, "claude-scriptcheck"), None);
}

#[skuld::test]
fn detect_empty_installs() {
    let json = serde_json::json!({ "installs": {} });
    assert_eq!(parse_install_source(&json, "claude-scriptcheck"), None);
}

#[skuld::test]
fn detect_malformed_key() {
    let json = serde_json::json!({
        "installs": {
            "claude-scriptcheck 0.1.0": {
                "bins": ["claude-scriptcheck"]
            }
        }
    });
    assert_eq!(parse_install_source(&json, "claude-scriptcheck"), None);
}

#[skuld::test]
fn detect_path_source_windows() {
    let json = serde_json::json!({
        "installs": {
            "claude-scriptcheck 0.1.0 (path+file:///C:/Users/dev/claude-scriptcheck)": {
                "bins": ["claude-scriptcheck"]
            }
        }
    });
    assert_eq!(
        parse_install_source(&json, "claude-scriptcheck"),
        Some(InstallSource::Path(
            "C:/Users/dev/claude-scriptcheck".into()
        ))
    );
}

#[skuld::test]
fn git_source_without_commit_hash() {
    let json = serde_json::json!({
        "installs": {
            "claude-scriptcheck 0.1.0 (git+https://github.com/bindreams/claude-scriptcheck.git)": {
                "bins": ["claude-scriptcheck"]
            }
        }
    });
    assert_eq!(
        parse_install_source(&json, "claude-scriptcheck"),
        Some(InstallSource::Git(
            "https://github.com/bindreams/claude-scriptcheck.git".into()
        ))
    );
}

// ── Install matcher tests ────────────────────────────────────────────────────

#[skuld::test]
fn supported_matchers_includes_all_tools() {
    for tool in ["Bash", "Monitor", "Grep", "Glob", "Read", "Write", "Edit"] {
        assert!(
            SUPPORTED_MATCHERS.contains(&tool),
            "SUPPORTED_MATCHERS should include {tool}",
        );
    }
}

#[skuld::test]
fn is_installed_for_matches_binary_and_matcher() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": binary }]
    })];
    assert!(is_installed_for(&entries, binary, "Bash"));
    assert!(!is_installed_for(&entries, binary, "Grep"));
    let other_entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/usr/bin/other-tool" }]
    })];
    assert!(!is_installed_for(&other_entries, binary, "Bash"));
}

#[skuld::test]
fn is_installed_for_no_false_positive_on_wrong_matcher() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let entries = vec![
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": binary }]
        }),
        serde_json::json!({
            "matcher": "Grep",
            "hooks": [{ "type": "command", "command": binary }]
        }),
    ];
    assert!(is_installed_for(&entries, binary, "Bash"));
    assert!(is_installed_for(&entries, binary, "Grep"));
    assert!(!is_installed_for(&entries, binary, "Read"));
}

#[skuld::test]
fn is_installed_for_empty_array() {
    let entries: Vec<serde_json::Value> = vec![];
    assert!(!is_installed_for(
        &entries,
        "/usr/bin/claude-scriptcheck",
        "Bash"
    ));
}

// ── Cross-format matching (bare name vs absolute path) ──────────────────────

#[skuld::test]
fn is_installed_for_matches_bare_against_absolute() {
    // Entry has bare name, lookup with absolute path from the current binary.
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": binary }]
    })];
    assert!(is_installed_for(&entries, binary, "Bash"));
}

#[skuld::test]
fn is_installed_for_treats_legacy_no_agent_hook_as_claude_owned() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": binary }]
    })];
    assert!(is_installed_for(&entries, binary, "Bash"));
}

#[skuld::test]
fn is_installed_for_treats_explicit_claude_hook_as_claude_owned() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": format!("{binary} --agent claude") }]
    })];
    assert!(is_installed_for(&entries, binary, "Bash"));
}

#[skuld::test]
fn is_installed_for_does_not_treat_codex_hook_as_claude_owned() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": format!("{binary} --agent codex") }]
    })];
    assert!(!is_installed_for(&entries, binary, "Bash"));
}

#[skuld::test]
fn is_installed_for_does_not_treat_foreign_path_hook_as_claude_owned() {
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/tmp/claude-scriptcheck" }]
    })];
    assert!(!is_installed_for(
        &entries,
        "/usr/local/bin/claude-scriptcheck",
        "Bash"
    ));
}

#[skuld::test]
fn binary_without_args_fails_before_hook_dispatch() {
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = std::process::Command::new(binary).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--agent"));
}

// ── Install/uninstall round-trip via binary ─────────────────────────────────

#[skuld::test]
fn install_uninstall_roundtrip() {
    use std::process::Command;

    let dir = std::env::temp_dir()
        .join("claude-scriptcheck-tests")
        .join("roundtrip");
    // Clean up from any prior failed run
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");

    // Install
    let output = Command::new(binary)
        .args(["install", "claude", "--project"])
        .current_dir(&dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let settings_path = dir.join(".claude/settings.json");
    let content = std::fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    let hooks = json["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse should be an array");
    assert_eq!(
        hooks.len(),
        SUPPORTED_MATCHERS.len(),
        "should have one entry per supported matcher"
    );

    // Every entry's command should include the explicit hook agent.
    for entry in hooks {
        let cmd = entry["hooks"][0]["command"]
            .as_str()
            .expect("command should be a string");
        assert!(
            cmd.contains("claude-scriptcheck"),
            "command should contain binary name, got: {cmd}"
        );
        assert!(
            cmd.contains("--agent claude"),
            "command should include explicit agent, got: {cmd}"
        );
    }

    // Verify all matchers are present
    for &matcher in SUPPORTED_MATCHERS {
        assert!(
            hooks.iter().any(|e| e["matcher"].as_str() == Some(matcher)),
            "missing matcher: {matcher}"
        );
    }

    // Uninstall
    let output = Command::new(binary)
        .args(["uninstall", "claude", "--project"])
        .current_dir(&dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(
        json.get("hooks").is_none(),
        "hooks should be removed after uninstall, got: {json}"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[skuld::test]
#[cfg(unix)]
fn install_via_bare_name_writes_bare_command() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let dir = std::env::temp_dir()
        .join("claude-scriptcheck-tests")
        .join("bare-name");
    let _ = std::fs::remove_dir_all(&dir);
    let bin_dir = dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    // Symlink the test binary into a temp bin/ directory
    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let link_path = bin_dir.join("claude-scriptcheck");
    symlink(binary, &link_path).unwrap();

    // Invoke via bare name by putting bin/ on PATH
    let output = Command::new("claude-scriptcheck")
        .args(["install", "claude", "--project"])
        .current_dir(&dir)
        .env("PATH", &bin_dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let settings_path = dir.join(".claude/settings.json");
    let content = std::fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    let hooks = json["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse should be an array");

    // The command should preserve bare-name invocation and add the explicit agent.
    let cmd = hooks[0]["hooks"][0]["command"]
        .as_str()
        .expect("command should be a string");
    assert_eq!(
        cmd, "claude-scriptcheck --agent claude",
        "bare-name invocation should write bare command with agent, got: {cmd}"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[skuld::test]
fn install_rewrites_only_targeted_scriptcheck_hook_commands() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let dir = std::env::temp_dir()
        .join("claude-scriptcheck-tests")
        .join("rewrite-targeting");
    let bin_dir = dir.join("bin");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(unix)]
    symlink(
        env!("CARGO_BIN_EXE_claude-scriptcheck"),
        bin_dir.join("claude-scriptcheck"),
    )
    .unwrap();
    #[cfg(windows)]
    std::fs::copy(
        env!("CARGO_BIN_EXE_claude-scriptcheck"),
        bin_dir.join("claude-scriptcheck.exe"),
    )
    .unwrap();

    std::fs::write(
        dir.join(".claude/settings.json"),
        serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
                    },
                    {
                        "matcher": "Grep",
                        "hooks": [{ "type": "command", "command": "'/tmp/claude-scriptcheck'" }]
                    },
                    {
                        "matcher": "Glob",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck --agent codex" }]
                    },
                    {
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck --agent=codex" }]
                    },
                    {
                        "matcher": "Write",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck --agent claude" }]
                    },
                    {
                        "matcher": "OtherEcho",
                        "hooks": [{ "type": "command", "command": "echo claude-scriptcheck" }]
                    },
                    {
                        "matcher": "OtherHelper",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck-helper --agent codex" }]
                    },
                    {
                        "matcher": "OtherScript",
                        "hooks": [{ "type": "command", "command": "python -c 'print(\"claude-scriptcheck\")'" }]
                    },
                    {
                        "matcher": "OtherNonCommand",
                        "hooks": [{ "type": "stdio", "command": "claude-scriptcheck --agent codex" }]
                    }
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = Command::new(binary)
        .args(["install", "claude", "--project"])
        .current_dir(&dir)
        .env("PATH", &bin_dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let settings_path = dir.join(".claude/settings.json");
    let content = std::fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let hooks = json["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse should be an array");

    let commands_for = |matcher: &str| {
        hooks
            .iter()
            .filter(|entry| entry["matcher"].as_str() == Some(matcher))
            .flat_map(|entry| {
                entry["hooks"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|hook| hook["command"].as_str().map(str::to_owned))
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(
        commands_for("Bash"),
        vec!["claude-scriptcheck --agent claude"]
    );
    assert_eq!(
        commands_for("Grep"),
        vec![
            "'/tmp/claude-scriptcheck'".to_string(),
            format!("{binary} --agent claude")
        ]
    );
    assert_eq!(
        commands_for("Glob"),
        vec![
            "claude-scriptcheck --agent codex".to_string(),
            format!("{binary} --agent claude")
        ]
    );
    assert_eq!(
        commands_for("Read"),
        vec![
            "claude-scriptcheck --agent=codex".to_string(),
            format!("{binary} --agent claude")
        ]
    );
    assert_eq!(
        commands_for("Write"),
        vec!["claude-scriptcheck --agent claude"]
    );
    assert_eq!(commands_for("OtherEcho"), vec!["echo claude-scriptcheck"]);
    assert_eq!(
        commands_for("OtherHelper"),
        vec!["claude-scriptcheck-helper --agent codex"]
    );
    assert_eq!(
        commands_for("OtherScript"),
        vec!["python -c 'print(\"claude-scriptcheck\")'"]
    );
    assert_eq!(
        commands_for("OtherNonCommand"),
        vec!["claude-scriptcheck --agent codex"]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[skuld::test]
fn uninstall_claude_preserves_codex_tagged_scriptcheck_hook_commands() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let dir = std::env::temp_dir()
        .join("claude-scriptcheck-tests")
        .join("uninstall-preserves-codex");
    let bin_dir = dir.join("bin");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(unix)]
    symlink(
        env!("CARGO_BIN_EXE_claude-scriptcheck"),
        bin_dir.join("claude-scriptcheck"),
    )
    .unwrap();
    #[cfg(windows)]
    std::fs::copy(
        env!("CARGO_BIN_EXE_claude-scriptcheck"),
        bin_dir.join("claude-scriptcheck.exe"),
    )
    .unwrap();

    std::fs::write(
        dir.join(".claude/settings.json"),
        serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
                    },
                    {
                        "matcher": "Grep",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck --agent claude" }]
                    },
                    {
                        "matcher": "Glob",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck --agent codex" }]
                    },
                    {
                        "matcher": "Read",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck --agent=codex" }]
                    },
                    {
                        "matcher": "OtherEcho",
                        "hooks": [{ "type": "command", "command": "echo claude-scriptcheck" }]
                    },
                    {
                        "matcher": "Monitor",
                        "hooks": [{ "type": "command", "command": "/tmp/claude-scriptcheck" }]
                    }
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = Command::new(binary)
        .args(["uninstall", "claude", "--project"])
        .current_dir(&dir)
        .env("PATH", &bin_dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let settings_path = dir.join(".claude/settings.json");
    let content = std::fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let hooks = json["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse should be an array");

    assert!(
        hooks
            .iter()
            .all(|entry| !matches!(entry["matcher"].as_str(), Some("Bash") | Some("Grep"))),
        "legacy/no-agent and Claude-owned entries should be removed: {json}"
    );
    assert!(
        hooks.iter().any(|entry| {
            entry["matcher"].as_str() == Some("Glob")
                && entry["hooks"][0]["command"].as_str() == Some("claude-scriptcheck --agent codex")
        }),
        "Codex-tagged entry should remain: {json}"
    );
    assert!(
        hooks.iter().any(|entry| {
            entry["matcher"].as_str() == Some("Read")
                && entry["hooks"][0]["command"].as_str() == Some("claude-scriptcheck --agent=codex")
        }),
        "Codex-tagged entry should remain: {json}"
    );
    assert!(
        hooks.iter().any(|entry| {
            entry["matcher"].as_str() == Some("OtherEcho")
                && entry["hooks"][0]["command"].as_str() == Some("echo claude-scriptcheck")
        }),
        "unrelated entries should remain: {json}"
    );
    assert!(
        hooks.iter().any(|entry| {
            entry["matcher"].as_str() == Some("Monitor")
                && entry["hooks"][0]["command"].as_str() == Some("/tmp/claude-scriptcheck")
        }),
        "foreign-path hooks should remain: {json}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[skuld::test]
#[cfg(unix)]
fn install_claude_preserves_foreign_bare_name_hook() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let dir = std::env::temp_dir()
        .join("claude-scriptcheck-tests")
        .join("install-preserves-foreign-bare");
    let bin_dir = dir.join("bin");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    symlink("/usr/bin/false", bin_dir.join("claude-scriptcheck")).unwrap();

    std::fs::write(
        dir.join(".claude/settings.json"),
        serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
                    }
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = Command::new(binary)
        .args(["install", "claude", "--project"])
        .current_dir(&dir)
        .env("PATH", &bin_dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(dir.join(".claude/settings.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let hooks = json["hooks"]["PreToolUse"].as_array().unwrap();
    let commands: Vec<String> = hooks
        .iter()
        .filter(|entry| entry["matcher"].as_str() == Some("Bash"))
        .flat_map(|entry| {
            entry["hooks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|hook| hook["command"].as_str().map(str::to_owned))
        })
        .collect();
    assert_eq!(
        commands,
        vec![
            "claude-scriptcheck".to_string(),
            format!("{binary} --agent claude")
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[skuld::test]
#[cfg(unix)]
fn uninstall_claude_preserves_foreign_bare_name_hook() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let dir = std::env::temp_dir()
        .join("claude-scriptcheck-tests")
        .join("uninstall-preserves-foreign-bare");
    let bin_dir = dir.join("bin");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".claude")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    symlink("/usr/bin/false", bin_dir.join("claude-scriptcheck")).unwrap();

    std::fs::write(
        dir.join(".claude/settings.json"),
        serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
                    }
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_claude-scriptcheck");
    let output = Command::new(binary)
        .args(["uninstall", "claude", "--project"])
        .current_dir(&dir)
        .env("PATH", &bin_dir)
        .output()
        .expect("Failed to run binary");
    assert!(
        output.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(dir.join(".claude/settings.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        json["hooks"]["PreToolUse"][0]["hooks"][0]["command"].as_str(),
        Some("claude-scriptcheck")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// Log filtering + tail integration tests ------------------------------------------------------------------------------

use claude_scriptcheck::logging;

fn make_log_content(verdicts: &[&str]) -> String {
    let mut content = String::new();
    for (i, v) in verdicts.iter().enumerate() {
        content.push_str(&format!(
            "---\ntimestamp: '2025-01-{:02}T00:00:00Z'\nsession: s{i}\ncwd: /tmp\ncommand: cmd{i}\nverdict: {v}\n\n",
            i + 1,
        ));
    }
    content
}

#[skuld::test]
fn log_split_roundtrip() {
    let content = make_log_content(&["allow", "deny", "ask"]);
    let docs = logging::split_documents(&content);
    assert_eq!(docs.len(), 3);
    assert_eq!(logging::extract_verdict(docs[0]), Some("allow".into()));
    assert_eq!(logging::extract_verdict(docs[1]), Some("deny".into()));
    assert_eq!(logging::extract_verdict(docs[2]), Some("ask".into()));
}

#[skuld::test]
fn log_verdict_filter_public_api() {
    use claude_scriptcheck::cli::VerdictFilter;

    let content = make_log_content(&["allow", "deny", "ask", "allow"]);
    let filter = VerdictFilter {
        show_allow: false,
        show_ask: true,
        show_deny: true,
    };
    let docs = logging::split_documents(&content);
    let filtered: Vec<_> = docs
        .into_iter()
        .filter(|doc| match logging::extract_verdict(doc) {
            Some(ref v) => filter.matches(v),
            None => true,
        })
        .collect();
    assert_eq!(filtered.len(), 2);
    assert_eq!(logging::extract_verdict(filtered[0]), Some("deny".into()));
    assert_eq!(logging::extract_verdict(filtered[1]), Some("ask".into()));
}
