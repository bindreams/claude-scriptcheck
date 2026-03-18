use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::Serialize;

const LOG_FILENAME: &str = "log.yaml";
const APP_DIR: &str = "claude-scriptcheck";

/// Returns the platform-appropriate log file path.
///
/// - Linux: `$XDG_STATE_HOME/claude-scriptcheck/log.yaml`
///          (defaults to `~/.local/state/claude-scriptcheck/log.yaml`)
/// - macOS: `~/Library/Logs/claude-scriptcheck/log.yaml`
/// - Fallback: `~/.local/share/claude-scriptcheck/log.yaml`
pub fn log_path() -> PathBuf {
    let base = if cfg!(target_os = "macos") {
        // macOS convention: ~/Library/Logs/
        dirs::home_dir().map(|h| h.join("Library/Logs"))
    } else {
        // Linux/other: $XDG_STATE_HOME or ~/.local/state
        dirs::state_dir()
    };

    base.or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_DIR)
        .join(LOG_FILENAME)
}

#[derive(Serialize)]
struct LogEntry<'a> {
    timestamp: String,
    session: &'a str,
    cwd: &'a str,
    command: &'a str,
    verdict: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allow_rules: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny_rules: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_rules: Vec<&'a str>,
}

pub fn log_decision(
    session: &str,
    cwd: &str,
    command: &str,
    verdict: &str,
    deny_reason: Option<&str>,
    allow_rules: &[String],
    deny_rules: &[String],
    missing_rules: &[String],
) {
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
    let timestamp = epoch_to_iso8601(epoch);

    let entry = LogEntry {
        timestamp,
        session,
        cwd,
        command,
        verdict,
        deny_reason,
        allow_rules: allow_rules.iter().map(|s| s.as_str()).collect(),
        deny_rules: deny_rules.iter().map(|s| s.as_str()).collect(),
        missing_rules: missing_rules.iter().map(|s| s.as_str()).collect(),
    };

    let Ok(yaml) = serde_yml::to_string(&entry) else {
        return;
    };

    let _ = write!(file, "---\n{yaml}\n");
}

fn epoch_to_iso8601(epoch: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch / secs_per_day;
    let remaining = epoch % secs_per_day;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719_468;
    let era = days / 146_097;
    let doe = days % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
