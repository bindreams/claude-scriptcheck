use crate::cli::{parse_install_source, InstallSource};


#[test]
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
        Some(InstallSource::Git("https://github.com/bindreams/claude-scriptcheck.git".into()))
    );
}

#[test]
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

#[test]
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
        Some(InstallSource::Path("/home/user/src/claude-scriptcheck".into()))
    );
}

#[test]
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

#[test]
fn detect_empty_installs() {
    let json = serde_json::json!({ "installs": {} });
    assert_eq!(parse_install_source(&json, "claude-scriptcheck"), None);
}

#[test]
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

#[test]
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
        Some(InstallSource::Git("https://github.com/bindreams/claude-scriptcheck.git".into()))
    );
}
