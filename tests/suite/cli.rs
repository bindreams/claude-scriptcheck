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
    for tool in ["Bash", "Grep", "Glob", "Read", "Write", "Edit"] {
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
