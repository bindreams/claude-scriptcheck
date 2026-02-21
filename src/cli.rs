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

/// Upgrade claude-scriptcheck to the latest version.
pub fn upgrade() {
    let status = std::process::Command::new("cargo")
        .args(["install", "--git", "https://github.com/bindreams/claude-scriptcheck.git"])
        .status()
        .unwrap_or_else(|e| {
            eprintln!("Failed to run cargo: {e}");
            process::exit(1);
        });

    process::exit(status.code().unwrap_or(1));
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
