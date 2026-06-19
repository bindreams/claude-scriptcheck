use std::path::{Path, PathBuf};
use std::process;

use crate::permission_mode::PermissionMode;
use crate::{checker, logging, path_util, permission};

const HOOK_ENTRY_MARKER: &str = "claude-scriptcheck";

/// Tool matchers that claude-scriptcheck handles. Each gets its own hook entry.
pub const SUPPORTED_MATCHERS: &[&str] =
    &["Bash", "Monitor", "Grep", "Glob", "Read", "Write", "Edit"];

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
///
/// `permission_mode` simulates Claude Code's mode for the dry run: the same
/// synthetic-rule injection and end-stage `apply_permission_mode` transform
/// run as in the hook path, so the dry run's verdict matches what the hook
/// would emit for the same input.
pub fn check(command: &str, cwd: &str, permission_mode: Option<PermissionMode>) {
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
    let parsed_perms = permission::load_perms(&resolved_cwd, &project_root, permission_mode);

    // Match the hook path: on parse failure, construct a synthetic Ask with
    // `custom_reason` and run it through `apply_permission_mode`, so the CLI
    // dry run's verdict matches the hook for unparseable input.
    let result = match thaum::parse_with(command, thaum::Dialect::Bash) {
        Ok(program) => checker::check_program(&program, &parsed_perms, &resolved_cwd),
        Err(_) => checker::CheckResult {
            decision: checker::Decision::Ask,
            matched_allow: vec![],
            matched_deny: vec![],
            missing_rules: vec!["Bash(<parse error>)".into()],
            custom_reason: Some("Shell command could not be parsed".into()),
        },
    };
    let result = checker::apply_permission_mode(result, permission_mode);

    match result.decision {
        checker::Decision::Allow => {
            let reason = result
                .custom_reason
                .as_deref()
                .unwrap_or("All commands and file accesses are permitted");
            println!("ALLOW: {reason}");
        }
        checker::Decision::Deny(reason) => {
            println!("DENY: {reason}");
            process::exit(1);
        }
        checker::Decision::Ask => {
            let header = result
                .custom_reason
                .as_deref()
                .unwrap_or("Missing permission rules");
            println!("ASK: {header}:");
            for rule in &result.missing_rules {
                println!("  - {rule}");
            }
        }
    }
}

/// Split content into YAML documents, filter by verdict, apply tail, return matching slices.
pub(crate) fn filter_and_tail<'a>(
    content: &'a str,
    filter: &VerdictFilter,
    tail: Option<usize>,
) -> Vec<&'a str> {
    let docs = logging::split_documents(content);
    let filtered: Vec<&str> = if filter.shows_all() {
        docs
    } else {
        docs.into_iter()
            .filter(|doc| match logging::extract_verdict(doc) {
                Some(ref v) => filter.matches(v),
                None => true,
            })
            .collect()
    };
    match tail {
        Some(n) => filtered[filtered.len().saturating_sub(n)..].to_vec(),
        None => filtered,
    }
}

/// Print the decision log.
pub fn log(clear: bool, follow: bool, tail: Option<usize>, filter: &VerdictFilter) {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::thread;
    use std::time::Duration;

    let path = logging::log_path();

    if follow {
        let mut stdout = std::io::stdout().lock();

        // Initial read: apply filter + tail
        let mut offset: u64 = 0;
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if !content.is_empty() {
                    let docs = filter_and_tail(&content, filter, tail);
                    for doc in &docs {
                        let _ = write!(stdout, "{doc}");
                    }
                    let _ = stdout.flush();
                }
                offset = content.len() as u64;
            }
        }

        // Streaming loop: filter only (no tail)
        let mut leftover = String::new();
        loop {
            thread::sleep(Duration::from_secs(1));
            let Ok(mut f) = std::fs::File::open(&path) else {
                offset = 0;
                leftover.clear();
                continue;
            };
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len < offset {
                offset = 0;
                leftover.clear();
            }
            if len == offset {
                // No new data — flush leftover if it looks complete.
                // A complete entry ends with `\n\n` (YAML body + trailing newline).
                if !leftover.is_empty() && leftover.ends_with("\n\n") {
                    let docs = logging::split_documents(&leftover);
                    for doc in docs {
                        match logging::extract_verdict(doc) {
                            Some(ref v) if !filter.matches(v) => {}
                            _ => {
                                let _ = write!(stdout, "{doc}");
                            }
                        }
                    }
                    let _ = stdout.flush();
                    leftover.clear();
                }
                continue;
            }
            let _ = f.seek(SeekFrom::Start(offset));
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            offset = f.stream_position().unwrap_or(len);

            if buf.is_empty() {
                continue;
            }

            // Prepend leftover from previous partial read
            let chunk = if leftover.is_empty() {
                buf
            } else {
                let mut combined = std::mem::take(&mut leftover);
                combined.push_str(&buf);
                combined
            };

            // A document is only guaranteed complete when the next `---\n`
            // boundary appears after it. Buffer the last chunk (which has no
            // following separator) as leftover for the next iteration.
            let docs = logging::split_documents(&chunk);
            if docs.is_empty() {
                leftover = chunk;
                continue;
            }
            let (complete_docs, trailing) = docs.split_at(docs.len() - 1);
            leftover = trailing[0].to_string();

            let mut any_printed = false;
            for doc in complete_docs {
                match logging::extract_verdict(doc) {
                    Some(ref v) if !filter.matches(v) => {}
                    _ => {
                        let _ = write!(stdout, "{doc}");
                        any_printed = true;
                    }
                }
            }
            if any_printed {
                let _ = stdout.flush();
            }
        }
    }

    // Non-follow path
    if !path.exists() {
        eprintln!("No log file found at {}", path.display());
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            if content.is_empty() {
                eprintln!("Log is empty.");
            } else {
                let docs = filter_and_tail(&content, filter, tail);
                for doc in &docs {
                    print!("{doc}");
                }
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

/// Returns the binary path to write into settings.json hook entries.
///
/// If argv[0] is a bare command name (no path separators), returns it as-is
/// so that settings.json uses PATH lookup — making it portable across machines.
/// Otherwise falls back to `current_exe()` for a resolved absolute path.
fn current_binary_path() -> String {
    match std::env::args().next() {
        // Bare command name (no path separators) → PATH lookup, keep as-is
        Some(argv0) if !argv0.is_empty() && !argv0.contains('/') && !argv0.contains('\\') => argv0,
        // Path-based invocation, empty argv[0], or missing argv → resolve to absolute
        _ => std::env::current_exe()
            .expect("Could not determine binary path")
            .to_string_lossy()
            .to_string(),
    }
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

// Verdict filtering ===================================================================================================

/// Controls which verdicts are displayed in log output.
#[derive(Debug)]
pub struct VerdictFilter {
    pub show_allow: bool,
    pub show_ask: bool,
    pub show_deny: bool,
}

impl VerdictFilter {
    /// Returns true if the given verdict should be shown.
    /// Unknown verdicts always pass.
    pub fn matches(&self, verdict: &str) -> bool {
        match verdict {
            "allow" => self.show_allow,
            "ask" => self.show_ask,
            "deny" => self.show_deny,
            _ => true,
        }
    }

    /// Returns true when all three verdict types are shown (no filtering needed).
    pub fn shows_all(&self) -> bool {
        self.show_allow && self.show_ask && self.show_deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // VerdictFilter tests ---------------------------------------------------------------------------------------------

    #[test]
    fn verdict_filter_matches_allow() {
        let f = VerdictFilter {
            show_allow: true,
            show_ask: false,
            show_deny: false,
        };
        assert!(f.matches("allow"));
    }

    #[test]
    fn verdict_filter_rejects_allow() {
        let f = VerdictFilter {
            show_allow: false,
            show_ask: true,
            show_deny: true,
        };
        assert!(!f.matches("allow"));
    }

    #[test]
    fn verdict_filter_matches_ask() {
        let f = VerdictFilter {
            show_allow: false,
            show_ask: true,
            show_deny: false,
        };
        assert!(f.matches("ask"));
    }

    #[test]
    fn verdict_filter_rejects_ask() {
        let f = VerdictFilter {
            show_allow: true,
            show_ask: false,
            show_deny: true,
        };
        assert!(!f.matches("ask"));
    }

    #[test]
    fn verdict_filter_matches_deny() {
        let f = VerdictFilter {
            show_allow: false,
            show_ask: false,
            show_deny: true,
        };
        assert!(f.matches("deny"));
    }

    #[test]
    fn verdict_filter_rejects_deny() {
        let f = VerdictFilter {
            show_allow: true,
            show_ask: true,
            show_deny: false,
        };
        assert!(!f.matches("deny"));
    }

    #[test]
    fn verdict_filter_unknown_passes() {
        let f = VerdictFilter {
            show_allow: false,
            show_ask: false,
            show_deny: false,
        };
        assert!(f.matches("something_else"));
    }

    #[test]
    fn verdict_filter_shows_all() {
        let f = VerdictFilter {
            show_allow: true,
            show_ask: true,
            show_deny: true,
        };
        assert!(f.shows_all());
    }

    #[test]
    fn verdict_filter_not_shows_all() {
        let f = VerdictFilter {
            show_allow: true,
            show_ask: false,
            show_deny: true,
        };
        assert!(!f.shows_all());
    }

    // filter_and_tail tests -------------------------------------------------------------------------------------------

    fn make_log(verdicts: &[&str]) -> String {
        let mut s = String::new();
        for (i, v) in verdicts.iter().enumerate() {
            s.push_str(&format!(
                "---\ntimestamp: '2025-01-{:02}T00:00:00Z'\nsession: s{i}\ncwd: /tmp\ncommand: cmd{i}\nverdict: {v}\n\n",
                i + 1,
            ));
        }
        s
    }

    #[test]
    fn filter_and_tail_no_filter_no_tail() {
        let content = make_log(&["allow", "deny", "ask"]);
        let all = VerdictFilter {
            show_allow: true,
            show_ask: true,
            show_deny: true,
        };
        let result = filter_and_tail(&content, &all, None);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn filter_and_tail_filters_verdict() {
        let content = make_log(&["allow", "deny", "ask", "allow"]);
        let f = VerdictFilter {
            show_allow: false,
            show_ask: true,
            show_deny: true,
        };
        let result = filter_and_tail(&content, &f, None);
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("deny"));
        assert!(result[1].contains("ask"));
    }

    #[test]
    fn filter_and_tail_applies_tail() {
        let content = make_log(&["allow", "deny", "ask", "allow", "deny"]);
        let all = VerdictFilter {
            show_allow: true,
            show_ask: true,
            show_deny: true,
        };
        let result = filter_and_tail(&content, &all, Some(2));
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("cmd3"));
        assert!(result[1].contains("cmd4"));
    }

    #[test]
    fn filter_and_tail_tail_after_filter() {
        let content = make_log(&["allow", "ask", "deny", "ask", "allow", "ask"]);
        let f = VerdictFilter {
            show_allow: false,
            show_ask: true,
            show_deny: false,
        };
        let result = filter_and_tail(&content, &f, Some(2));
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("cmd3"));
        assert!(result[1].contains("cmd5"));
    }

    #[test]
    fn filter_and_tail_tail_zero() {
        let content = make_log(&["allow", "deny"]);
        let all = VerdictFilter {
            show_allow: true,
            show_ask: true,
            show_deny: true,
        };
        let result = filter_and_tail(&content, &all, Some(0));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_and_tail_tail_exceeds_count() {
        let content = make_log(&["allow", "deny"]);
        let all = VerdictFilter {
            show_allow: true,
            show_ask: true,
            show_deny: true,
        };
        let result = filter_and_tail(&content, &all, Some(100));
        assert_eq!(result.len(), 2);
    }

    // ExeRenameGuard tests (Windows only) -----------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    use std::fs;

    #[cfg(target_os = "windows")]
    fn temp_exe_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("claude-scriptcheck-tests");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    #[cfg(target_os = "windows")]
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

    #[test]
    #[cfg(target_os = "windows")]
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

    #[test]
    #[cfg(target_os = "windows")]
    fn guard_deletes_old_on_cleanup_when_disarmed() {
        let path = temp_exe_path("guard_disarmed.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"original").unwrap();

        let mut guard = ExeRenameGuard::new(path.clone()).unwrap();
        guard.disarm();
        guard.cleanup();

        assert!(!path.exists(), "original was renamed and not restored");
        assert!(!old_path.exists(), ".old should be deleted");
    }

    #[test]
    #[cfg(target_os = "windows")]
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

    #[test]
    #[cfg(target_os = "windows")]
    fn guard_restores_via_drop() {
        let path = temp_exe_path("guard_drop.exe");
        let old_path = PathBuf::from(format!("{}.old", path.display()));
        fs::write(&path, b"original").unwrap();

        {
            let _guard = ExeRenameGuard::new(path.clone()).unwrap();
        }

        assert!(path.exists(), "Drop should restore the original");
        assert!(!old_path.exists(), ".old should be gone after Drop");

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn guard_cleanup_is_idempotent() {
        let path = temp_exe_path("guard_idempotent.exe");
        let old_path = PathBuf::from({
            let mut s = path.as_os_str().to_os_string();
            s.push(".old");
            s
        });
        fs::write(&path, b"original").unwrap();

        let mut guard = ExeRenameGuard::new(path.clone()).unwrap();
        guard.cleanup();
        assert!(path.exists());
        assert!(!old_path.exists());

        guard.cleanup();
        assert!(path.exists());
        assert!(!old_path.exists());

        drop(guard);
        assert!(path.exists());
        assert!(!old_path.exists());

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn guard_new_fails_if_file_missing() {
        let path = temp_exe_path("guard_missing.exe");
        let _ = fs::remove_file(&path);

        let result = ExeRenameGuard::new(path);
        assert!(result.is_err());
    }
}
