use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

const LOG_FILENAME: &str = "missing-rules.log";
const APP_DIR: &str = "claude-scriptcheck";

/// Returns the platform-appropriate log file path.
///
/// - Linux: `$XDG_STATE_HOME/claude-scriptcheck/missing-rules.log`
///          (defaults to `~/.local/state/claude-scriptcheck/missing-rules.log`)
/// - macOS: `~/Library/Logs/claude-scriptcheck/missing-rules.log`
/// - Fallback: `~/.local/share/claude-scriptcheck/missing-rules.log`
pub fn log_path() -> PathBuf {
    let base = if cfg!(target_os = "macos") {
        // macOS convention: ~/Library/Logs/
        dirs::home_dir().map(|h| h.join("Library/Logs"))
    } else {
        // Linux/other: $XDG_STATE_HOME or ~/.local/state
        dirs::state_dir()
    };

    base.or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(APP_DIR)
        .join(LOG_FILENAME)
}

pub fn log_missing_rules(rules: &[String], command: &str) {
    let path = log_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };

    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let _ = writeln!(file, "--- {epoch} ---");
    let _ = writeln!(file, "command: {command}");
    for rule in rules {
        let _ = writeln!(file, "  missing: {rule}");
    }
    let _ = writeln!(file);
}
