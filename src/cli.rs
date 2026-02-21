use std::path::{Path, PathBuf};
use std::process;

use crate::{checker, logging, permission, settings};

const HOOK_ENTRY_MARKER: &str = "claude-scriptcheck";

/// Install the hook into Claude settings.
pub fn install(project: bool) {
    let settings_path = settings_path(project);
    let binary_path = current_binary_path();

    let mut root = read_settings_json(&settings_path);

    // Ensure "hooks" object exists
    if root.get("hooks").is_none() {
        root.as_object_mut()
            .unwrap()
            .insert("hooks".to_string(), serde_json::json!({}));
    }
    let hooks = root["hooks"].as_object_mut().unwrap();

    // Ensure "PreToolUse" array exists
    if hooks.get("PreToolUse").is_none() {
        hooks.insert("PreToolUse".to_string(), serde_json::json!([]));
    }
    let pre_tool_use = hooks["PreToolUse"].as_array_mut().unwrap();

    // Check if already installed
    if is_installed(pre_tool_use, &binary_path) {
        eprintln!("Hook is already installed in {}", settings_path.display());
        return;
    }

    // Add the hook entry
    let entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": binary_path
            }
        ]
    });
    pre_tool_use.push(entry);

    write_settings_json(&settings_path, &root);
    eprintln!("Installed hook in {}", settings_path.display());
    eprintln!("Binary: {binary_path}");
}

/// Uninstall the hook from Claude settings.
pub fn uninstall(project: bool) {
    let settings_path = settings_path(project);
    let binary_path = current_binary_path();

    let mut root = read_settings_json(&settings_path);

    let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        eprintln!("No hooks section found in {}", settings_path.display());
        return;
    };

    let Some(pre_tool_use) = hooks.get_mut("PreToolUse").and_then(|p| p.as_array_mut()) else {
        eprintln!("No PreToolUse hooks found in {}", settings_path.display());
        return;
    };

    let before = pre_tool_use.len();
    pre_tool_use.retain(|entry| !entry_matches(entry, &binary_path));
    let after = pre_tool_use.len();

    if before == after {
        eprintln!("Hook was not installed in {}", settings_path.display());
        return;
    }

    // Clean up empty arrays/objects
    if pre_tool_use.is_empty() {
        hooks.remove("PreToolUse");
    }
    if hooks.is_empty() {
        root.as_object_mut().unwrap().remove("hooks");
    }

    write_settings_json(&settings_path, &root);
    eprintln!("Uninstalled hook from {}", settings_path.display());
}

/// Manually check a command against permission rules.
pub fn check(command: &str, cwd: &str) {
    let resolved_cwd = if cwd == "." {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .to_string_lossy()
            .to_string()
    } else {
        cwd.to_string()
    };

    let permissions = settings::load_settings(&resolved_cwd);
    let parsed_perms = permission::parse_rules(&permissions);

    let program = match thaum::parse_with(command, thaum::Dialect::Bash) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse error: {e}");
            process::exit(1);
        }
    };

    let decision = checker::check_program(&program, &parsed_perms, &resolved_cwd);

    match decision {
        checker::Decision::Allow => {
            println!("ALLOW: All commands and file accesses are permitted");
        }
        checker::Decision::Deny(reason) => {
            println!("DENY: {reason}");
            process::exit(1);
        }
        checker::Decision::Ask(missing) => {
            println!("ASK: Missing permission rules:");
            for rule in &missing {
                println!("  - {rule}");
            }
        }
    }
}

/// Print the missing-rules log.
pub fn log(clear: bool) {
    let path = logging::log_path();
    if !path.exists() {
        eprintln!("No log file found at {}", path.display());
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            if content.is_empty() {
                eprintln!("Log is empty.");
            } else {
                print!("{content}");
            }
        }
        Err(e) => {
            eprintln!("Failed to read log at {}: {e}", path.display());
            process::exit(1);
        }
    }
    if clear {
        let _ = std::fs::remove_file(&path);
        eprintln!("Log cleared.");
    }
}

const CRATE_NAME: &str = "claude-scriptcheck";
const DEFAULT_GIT_URL: &str = "https://github.com/bindreams/claude-scriptcheck.git";

/// Installation source detected from cargo metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InstallSource {
    Git(String),
    Registry,
    Path(String),
}

/// Upgrade claude-scriptcheck to the latest version, respecting the original install source.
pub fn upgrade() {
    let source = detect_install_source();
    let mut cmd = std::process::Command::new("cargo");

    match &source {
        Some(InstallSource::Git(url)) => {
            eprintln!("Upgrading {CRATE_NAME} (installed from git: {url})");
            cmd.args(["install", "--git", url]);
        }
        Some(InstallSource::Registry) => {
            eprintln!("Upgrading {CRATE_NAME} (installed from crates.io)");
            cmd.args(["install", CRATE_NAME]);
        }
        Some(InstallSource::Path(path)) => {
            eprintln!("Upgrading {CRATE_NAME} (installed from path: {path})");
            cmd.args(["install", "--path", path]);
        }
        None => {
            eprintln!("Upgrading {CRATE_NAME} (install source unknown, defaulting to git)");
            cmd.args(["install", "--git", DEFAULT_GIT_URL]);
        }
    }

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("Failed to run cargo: {e}");
        process::exit(1);
    });

    process::exit(status.code().unwrap_or(1));
}

fn detect_install_source() -> Option<InstallSource> {
    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cargo")))?;

    let crates_file = cargo_home.join(".crates2.json");
    let content = std::fs::read_to_string(crates_file).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    parse_install_source(&json, CRATE_NAME)
}

fn parse_install_source(
    crates_json: &serde_json::Value,
    crate_name: &str,
) -> Option<InstallSource> {
    let installs = crates_json.get("installs")?.as_object()?;
    let prefix = format!("{crate_name} ");

    for key in installs.keys() {
        if !key.starts_with(&prefix) {
            continue;
        }

        // Key format: "name version (source_id)"
        let open = key.find('(')?;
        let close = key.rfind(')')?;
        if open >= close {
            return None;
        }
        let source_id = &key[open + 1..close];

        if let Some(url) = source_id.strip_prefix("git+") {
            // Strip the #commit_hash suffix
            let url = url.split('#').next().unwrap_or(url);
            return Some(InstallSource::Git(url.to_string()));
        } else if source_id.starts_with("registry+") {
            return Some(InstallSource::Registry);
        } else if let Some(path) = source_id.strip_prefix("path+file://") {
            return Some(InstallSource::Path(path.to_string()));
        }

        return None;
    }

    None
}

/// Print the path to the log file.
pub fn log_path() {
    println!("{}", logging::log_path().display());
}

fn settings_path(project: bool) -> PathBuf {
    if project {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        cwd.join(".claude/settings.json")
    } else {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".claude/settings.json")
    }
}

fn current_binary_path() -> String {
    std::env::current_exe()
        .expect("Could not determine binary path")
        .to_string_lossy()
        .to_string()
}

fn read_settings_json(path: &Path) -> serde_json::Value {
    if path.exists() {
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("Failed to read {}: {e}", path.display());
            process::exit(1);
        });
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("Failed to parse {}: {e}", path.display());
            process::exit(1);
        })
    } else {
        serde_json::json!({})
    }
}

fn write_settings_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directory {}: {e}", parent.display());
            process::exit(1);
        });
    }
    let content = serde_json::to_string_pretty(value).unwrap();
    std::fs::write(path, content).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {e}", path.display());
        process::exit(1);
    });
}

fn is_installed(pre_tool_use: &[serde_json::Value], binary_path: &str) -> bool {
    pre_tool_use.iter().any(|entry| entry_matches(entry, binary_path))
}

fn entry_matches(entry: &serde_json::Value, binary_path: &str) -> bool {
    // Match by checking if any hook command contains our binary path or marker
    if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
        for hook in hooks {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                if cmd == binary_path || cmd.contains(HOOK_ENTRY_MARKER) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
