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
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/usr/bin/claude-scriptcheck" }]
    })];
    assert!(is_installed_for(
        &entries,
        "/usr/bin/claude-scriptcheck",
        "Bash"
    ));
    assert!(!is_installed_for(
        &entries,
        "/usr/bin/claude-scriptcheck",
        "Grep"
    ));
    // entry_matches also matches by marker substring, so any binary path matches
    // if the entry command contains "claude-scriptcheck". Test with a non-matching entry:
    let other_entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/usr/bin/other-tool" }]
    })];
    assert!(!is_installed_for(
        &other_entries,
        "/usr/bin/claude-scriptcheck",
        "Bash"
    ));
}

#[skuld::test]
fn is_installed_for_no_false_positive_on_wrong_matcher() {
    let entries = vec![
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "/usr/bin/claude-scriptcheck" }]
        }),
        serde_json::json!({
            "matcher": "Grep",
            "hooks": [{ "type": "command", "command": "/usr/bin/claude-scriptcheck" }]
        }),
    ];
    assert!(is_installed_for(
        &entries,
        "/usr/bin/claude-scriptcheck",
        "Bash"
    ));
    assert!(is_installed_for(
        &entries,
        "/usr/bin/claude-scriptcheck",
        "Grep"
    ));
    assert!(!is_installed_for(
        &entries,
        "/usr/bin/claude-scriptcheck",
        "Read"
    ));
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
fn is_installed_for_matches_bare_command_name() {
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
    })];
    assert!(is_installed_for(&entries, "claude-scriptcheck", "Bash"));
}

#[skuld::test]
fn is_installed_for_matches_absolute_against_bare() {
    // Entry has absolute path, lookup with bare name — marker match on cmd
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "/usr/local/bin/claude-scriptcheck" }]
    })];
    assert!(is_installed_for(&entries, "claude-scriptcheck", "Bash"));
}

#[skuld::test]
fn is_installed_for_matches_bare_against_absolute() {
    // Entry has bare name, lookup with absolute path — marker match on cmd
    let entries = vec![serde_json::json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
    })];
    assert!(is_installed_for(
        &entries,
        "/usr/local/bin/claude-scriptcheck",
        "Bash"
    ));
}

#[skuld::test]
fn is_installed_for_mixed_format_no_duplicate() {
    // Simulates: first install wrote bare name, second install checks with absolute path.
    // Should detect existing entry via marker and avoid duplicates.
    let entries = vec![
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
        }),
        serde_json::json!({
            "matcher": "Grep",
            "hooks": [{ "type": "command", "command": "claude-scriptcheck" }]
        }),
    ];
    // Both matchers detected as installed regardless of binary_path format
    assert!(is_installed_for(
        &entries,
        "/home/user/.cargo/bin/claude-scriptcheck",
        "Bash"
    ));
    assert!(is_installed_for(
        &entries,
        "/home/user/.cargo/bin/claude-scriptcheck",
        "Grep"
    ));
    // Unrelated matcher still not installed
    assert!(!is_installed_for(
        &entries,
        "/home/user/.cargo/bin/claude-scriptcheck",
        "Read"
    ));
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
        .args(["install", "--project"])
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

    // Every entry's command should contain "claude-scriptcheck"
    for entry in hooks {
        let cmd = entry["hooks"][0]["command"]
            .as_str()
            .expect("command should be a string");
        assert!(
            cmd.contains("claude-scriptcheck"),
            "command should contain binary name, got: {cmd}"
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
        .args(["uninstall", "--project"])
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
        .args(["install", "--project"])
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

    // The command should be the bare name "claude-scriptcheck", not an absolute path
    let cmd = hooks[0]["hooks"][0]["command"]
        .as_str()
        .expect("command should be a string");
    assert_eq!(
        cmd, "claude-scriptcheck",
        "bare-name invocation should write bare command, got: {cmd}"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

// Log filtering + tail integration tests -----

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
