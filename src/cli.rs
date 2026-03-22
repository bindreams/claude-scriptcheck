use std::path::{Path, PathBuf};
use std::process;

use crate::{checker, logging, path_util, permission, settings};

const HOOK_ENTRY_MARKER: &str = "claude-scriptcheck";

/// Tool matchers that claude-scriptcheck handles. Each gets its own hook entry.
pub const SUPPORTED_MATCHERS: &[&str] = &["Bash", "Grep", "Glob", "Read", "Write", "Edit"];

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

    // Add entries for any missing matchers
    let mut added = Vec::new();
    for &matcher in SUPPORTED_MATCHERS {
        if !is_installed_for(pre_tool_use, &binary_path, matcher) {
            let entry = serde_json::json!({
                "matcher": matcher,
                "hooks": [
                    {
                        "type": "command",
                        "command": binary_path
                    }
                ]
            });
            pre_tool_use.push(entry);
            added.push(matcher);
        }
    }

    if added.is_empty() {
        eprintln!("Hook is already installed in {}", settings_path.display());
        return;
    }

    write_settings_json(&settings_path, &root);
    eprintln!(
        "Installed hook for {} in {}",
        added.join(", "),
        settings_path.display()
    );
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
    let resolved_cwd = path_util::normalize_separators(&resolved_cwd);

    let project_root = std::env::var("CLAUDE_PROJECT_DIR")
        .map(|s| path_util::normalize_separators(&s))
        .unwrap_or_else(|_| resolved_cwd.clone());
    let permissions = settings::load_settings(&resolved_cwd, &project_root);
    let parsed_perms = permission::parse_rules(&permissions);

    let program = match thaum::parse_with(command, thaum::Dialect::Bash) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse error: {e}");
            process::exit(1);
        }
    };

    let result = checker::check_program(&program, &parsed_perms, &resolved_cwd);

    match result.decision {
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

/// Print the decision log.
pub fn log(clear: bool, watch: bool) {
    use std::io::{Read, Seek, SeekFrom};
    use std::thread;
    use std::time::Duration;

    let path = logging::log_path();

    if watch {
        let mut offset: u64 = 0;
        if path.exists() {
            if let Ok(mut f) = std::fs::File::open(&path) {
                let mut buf = String::new();
                let _ = f.read_to_string(&mut buf);
                if !buf.is_empty() {
                    print!("{buf}");
                }
                offset = f.stream_position().unwrap_or(0);
            }
        }
        loop {
            thread::sleep(Duration::from_secs(1));
            let Ok(mut f) = std::fs::File::open(&path) else {
                offset = 0;
                continue;
            };
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len < offset {
                offset = 0; // file was truncated
            }
            if len == offset {
                continue; // no new data
            }
            let _ = f.seek(SeekFrom::Start(offset));
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            if !buf.is_empty() {
                print!("{buf}");
            }
            offset = f.stream_position().unwrap_or(len);
        }
    }

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
pub enum InstallSource {
    Git(String),
    Registry,
    Path(String),
}

// Windows upgrade guard ===============================================================================================

/// Renames the running executable to `{path}.old` so `cargo install` can write a new binary to
/// the original path. Must call [`cleanup()`](ExeRenameGuard::cleanup) explicitly before
/// `process::exit`, since exit skips destructors. [`Drop`] is implemented as a safety net for
/// panic unwinding.
#[cfg(target_os = "windows")]
struct ExeRenameGuard {
    original: PathBuf,
    renamed: PathBuf,
    disarmed: bool,
    done: bool,
}

#[cfg(target_os = "windows")]
impl ExeRenameGuard {
    fn new(exe_path: PathBuf) -> Result<Self, String> {
        let mut renamed_os = exe_path.as_os_str().to_os_string();
        renamed_os.push(".old");
        let renamed = PathBuf::from(renamed_os);

        // Remove stale .old from a prior failed upgrade.
        if renamed.exists() {
            std::fs::remove_file(&renamed).map_err(|e| {
                format!(
                    "Failed to remove stale {}: {e} (another upgrade may be in progress)",
                    renamed.display()
                )
            })?;
        }

        std::fs::rename(&exe_path, &renamed).map_err(|e| {
            format!(
                "Failed to rename {} → {}: {e}",
                exe_path.display(),
                renamed.display()
            )
        })?;

        Ok(Self {
            original: exe_path,
            renamed,
            disarmed: false,
            done: false,
        })
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }

    fn cleanup(&mut self) {
        if self.done {
            return;
        }
        self.done = true;

        if self.disarmed {
            // Success path: delete the old binary (best-effort).
            if let Err(e) = std::fs::remove_file(&self.renamed) {
                eprintln!("Warning: could not remove {}: {e}", self.renamed.display());
            }
        } else {
            // Failure path: restore the original binary.
            // On Windows, fs::rename fails if the target exists (e.g. cargo install left a
            // partial binary). Remove it first so the restore can succeed.
            let _ = std::fs::remove_file(&self.original);
            if let Err(e) = std::fs::rename(&self.renamed, &self.original) {
                eprintln!(
                    "Failed to restore {} from {}: {e}",
                    self.original.display(),
                    self.renamed.display()
                );
                eprintln!(
                    "Manual recovery: rename {} back to {}",
                    self.renamed.display(),
                    self.original.display()
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for ExeRenameGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
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

    #[cfg(target_os = "windows")]
    let mut guard = {
        let exe = std::env::current_exe().unwrap_or_else(|e| {
            eprintln!("Failed to determine executable path: {e}");
            process::exit(1);
        });
        ExeRenameGuard::new(exe).unwrap_or_else(|e| {
            eprintln!("Failed to prepare upgrade: {e}");
            process::exit(1);
        })
    };

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("Failed to run cargo: {e}");
        #[cfg(target_os = "windows")]
        guard.cleanup();
        process::exit(1);
    });

    #[cfg(target_os = "windows")]
    {
        if status.success() {
            guard.disarm();
        }
        guard.cleanup();
    }

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

pub fn parse_install_source(
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
            // file:/// URLs use 3 slashes, so after stripping "path+file://" the
            // remainder starts with "/". Strip that slash and keep the result only
            // if it is already an absolute path (e.g. "C:/..." on Windows);
            // otherwise the slash is the Unix root and must stay.
            let path = path
                .strip_prefix('/')
                .filter(|p| path_util::is_absolute(p))
                .unwrap_or(path);
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

/// Check if a hook entry exists for a specific matcher and binary path.
pub fn is_installed_for(
    pre_tool_use: &[serde_json::Value],
    binary_path: &str,
    matcher: &str,
) -> bool {
    pre_tool_use.iter().any(|entry| {
        let matcher_matches = entry
            .get("matcher")
            .and_then(|m| m.as_str())
            .is_some_and(|m| m == matcher);
        matcher_matches && entry_matches(entry, binary_path)
    })
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;
    use std::fs;

    fn temp_exe_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("claude-scriptcheck-tests");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[skuld::test]
    fn guard_renames_file_to_old() {
        let path = temp_exe_path("guard_renames.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"original").unwrap();

        let _guard = ExeRenameGuard::new(path.clone()).unwrap();

        assert!(!path.exists(), "original should be renamed away");
        assert!(old_path.exists(), ".old should exist");
        assert_eq!(fs::read(&old_path).unwrap(), b"original");

        // Cleanup
        let _ = fs::remove_file(&old_path);
        let _ = fs::remove_file(&path);
    }

    #[skuld::test]
    fn guard_restores_on_cleanup_when_not_disarmed() {
        let path = temp_exe_path("guard_restores.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"original").unwrap();

        let mut guard = ExeRenameGuard::new(path.clone()).unwrap();
        guard.cleanup();

        assert!(path.exists(), "original should be restored");
        assert!(!old_path.exists(), ".old should be gone");
        assert_eq!(fs::read(&path).unwrap(), b"original");

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[skuld::test]
    fn guard_deletes_old_on_cleanup_when_disarmed() {
        let path = temp_exe_path("guard_disarmed.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"original").unwrap();

        let mut guard = ExeRenameGuard::new(path.clone()).unwrap();
        guard.disarm();
        guard.cleanup();

        assert!(!path.exists(), "original was renamed and not restored");
        assert!(!old_path.exists(), ".old should be deleted");

        // Cleanup (nothing to do, both gone)
    }

    #[skuld::test]
    fn guard_removes_stale_old_before_renaming() {
        let path = temp_exe_path("guard_stale.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"current").unwrap();
        fs::write(&old_path, b"stale").unwrap();

        let _guard = ExeRenameGuard::new(path.clone()).unwrap();

        assert!(!path.exists());
        assert_eq!(
            fs::read(&old_path).unwrap(),
            b"current",
            "stale .old should be replaced"
        );

        // Cleanup
        let _ = fs::remove_file(&old_path);
        let _ = fs::remove_file(&path);
    }

    #[skuld::test]
    fn guard_restores_via_drop() {
        let path = temp_exe_path("guard_drop.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"original").unwrap();

        {
            let _guard = ExeRenameGuard::new(path.clone()).unwrap();
            // guard drops here without explicit cleanup
        }

        assert!(path.exists(), "Drop should restore the original");
        assert!(!old_path.exists(), ".old should be gone after Drop");

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[skuld::test]
    fn guard_cleanup_is_idempotent() {
        let path = temp_exe_path("guard_idempotent.exe");
        let old_path = PathBuf::from({
            let mut s = path.as_os_str().to_os_string();
            s.push(".old");
            s
        });
        fs::write(&path, b"original").unwrap();

        let mut guard = ExeRenameGuard::new(path.clone()).unwrap();
        guard.cleanup(); // first cleanup restores
        assert!(path.exists());
        assert!(!old_path.exists());

        guard.cleanup(); // second cleanup is a no-op
        assert!(path.exists());
        assert!(!old_path.exists());

        drop(guard); // Drop also calls cleanup — should be a no-op
        assert!(path.exists());
        assert!(!old_path.exists());

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[skuld::test]
    fn guard_new_fails_if_file_missing() {
        let path = temp_exe_path("guard_missing.exe");
        let _ = fs::remove_file(&path); // ensure it doesn't exist

        let result = ExeRenameGuard::new(path);
        assert!(result.is_err());
    }
}
