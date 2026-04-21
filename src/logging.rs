use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

const LOG_FILENAME: &str = "log.yaml";
const APP_DIR: &str = "claude-scriptcheck";

/// Returns the platform-appropriate log file path.
///
/// - Linux: `$XDG_STATE_HOME/claude-scriptcheck/log.yaml`
///   (defaults to `~/.local/state/claude-scriptcheck/log.yaml`)
/// - macOS: `~/Library/Logs/claude-scriptcheck/log.yaml`
/// - Fallback: `~/.local/share/claude-scriptcheck/log.yaml`
///
/// `CLAUDE_SCRIPTCHECK_LOG_PATH` overrides the result when set (test isolation).
pub fn log_path() -> PathBuf {
    if let Some(override_path) = crate::env_hooks::log_path_override() {
        return override_path;
    }

    let base = if cfg!(target_os = "macos") {
        // macOS convention: ~/Library/Logs/
        crate::env_hooks::hook_home().map(|h| h.join("Library/Logs"))
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
    #[serde(skip_serializing_if = "str::is_empty")]
    project_dir: &'a str,
    command: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_mode: Option<&'a str>,
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

#[allow(clippy::too_many_arguments)]
pub fn log_decision(
    session: &str,
    cwd: &str,
    project_dir: &str,
    command: &str,
    permission_mode: Option<&str>,
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

    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) else {
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
        project_dir,
        command,
        permission_mode,
        verdict,
        deny_reason,
        allow_rules: allow_rules.iter().map(|s| s.as_str()).collect(),
        deny_rules: deny_rules.iter().map(|s| s.as_str()).collect(),
        missing_rules: missing_rules.iter().map(|s| s.as_str()).collect(),
    };

    let Ok(yaml) = yaml_serde::to_string(&entry) else {
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

// Parsing helpers =====

/// Minimal struct to extract the verdict field from a log entry.
#[derive(Deserialize)]
struct VerdictOnly {
    #[serde(default)]
    verdict: String,
}

/// Split a YAML multi-document log string into individual document slices.
///
/// Each returned slice starts with `---\n`. Splitting on `---\n` at column 0 is
/// safe because the YAML spec guarantees that `---` at column 0 is always a
/// document separator — a YAML serializer will never produce it within a document body.
pub fn split_documents(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }

    let mut boundaries = Vec::new();
    let bytes = content.as_bytes();

    for (i, _) in content.match_indices("---\n") {
        if i == 0 || bytes[i - 1] == b'\n' {
            boundaries.push(i);
        }
    }

    if boundaries.is_empty() {
        return Vec::new();
    }

    let mut docs = Vec::with_capacity(boundaries.len());
    for pair in boundaries.windows(2) {
        docs.push(&content[pair[0]..pair[1]]);
    }
    docs.push(&content[*boundaries.last().unwrap()..]);
    docs
}

/// Extract the verdict field from a raw YAML document string.
///
/// Returns `None` if the document cannot be parsed or the verdict field is empty.
pub fn extract_verdict(doc: &str) -> Option<String> {
    let body = doc.strip_prefix("---\n").unwrap_or(doc);
    let parsed: VerdictOnly = yaml_serde::from_str(body).ok()?;
    if parsed.verdict.is_empty() {
        None
    } else {
        Some(parsed.verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // yaml_serde output format -----

    #[test]
    fn yaml_serde_output_format() {
        let entry = LogEntry {
            timestamp: "2025-01-01T00:00:00Z".into(),
            session: "s1",
            cwd: "/tmp",
            project_dir: "",
            command: "ls",
            permission_mode: None,
            verdict: "allow",
            deny_reason: None,
            allow_rules: vec![],
            deny_rules: vec![],
            missing_rules: vec![],
        };
        let yaml = yaml_serde::to_string(&entry).unwrap();
        assert!(
            !yaml.starts_with("---"),
            "yaml_serde should not produce a leading `---` marker, got:\n{yaml}"
        );
        assert!(
            yaml.ends_with('\n'),
            "yaml_serde should produce trailing newline, got:\n{yaml:?}"
        );
        // Lock in the `skip_serializing_if` contract: empty project_dir and
        // None permission_mode must be omitted so legacy log entries stay clean.
        assert!(
            !yaml.contains("project_dir:"),
            "empty project_dir must be omitted, got:\n{yaml}"
        );
        assert!(
            !yaml.contains("permission_mode:"),
            "None permission_mode must be omitted, got:\n{yaml}"
        );
    }

    /// Populated project_dir and permission_mode must appear in the YAML output.
    /// Note: both fields have `skip_serializing_if` — an empty `project_dir` or
    /// `None` `permission_mode` will be omitted, so this test MUST use non-empty
    /// / `Some(...)` literals or the assertion becomes silently meaningless.
    #[test]
    fn yaml_serde_output_includes_permission_mode_and_project_dir() {
        let entry = LogEntry {
            timestamp: "2025-01-01T00:00:00Z".into(),
            session: "s1",
            cwd: "/tmp",
            project_dir: "/proj",
            command: "ls",
            permission_mode: Some("acceptEdits"),
            verdict: "allow",
            deny_reason: None,
            allow_rules: vec![],
            deny_rules: vec![],
            missing_rules: vec![],
        };
        let yaml = yaml_serde::to_string(&entry).unwrap();
        assert!(
            yaml.contains("project_dir:"),
            "serialized YAML should contain project_dir key, got:\n{yaml}"
        );
        assert!(
            yaml.contains("/proj"),
            "serialized YAML should contain project_dir value, got:\n{yaml}"
        );
        assert!(
            yaml.contains("permission_mode:"),
            "serialized YAML should contain permission_mode key, got:\n{yaml}"
        );
        assert!(
            yaml.contains("acceptEdits"),
            "serialized YAML should contain permission_mode value, got:\n{yaml}"
        );
    }

    #[test]
    fn yaml_serde_output_with_populated_lists() {
        let entry = LogEntry {
            timestamp: "2025-01-01T00:00:00Z".into(),
            session: "s1",
            cwd: "/tmp",
            project_dir: "",
            command: "Read(/some/path)",
            permission_mode: None,
            verdict: "allow",
            deny_reason: None,
            allow_rules: vec!["Read(**)"],
            deny_rules: vec![],
            missing_rules: vec![],
        };
        let yaml = yaml_serde::to_string(&entry).unwrap();
        assert!(
            !yaml.starts_with("---"),
            "yaml_serde should not produce a leading `---` marker with populated lists, got:\n{yaml}"
        );
    }

    /// Verify that log_decision writes entries that round-trip through split + extract.
    #[test]
    fn log_entry_format_roundtrips() {
        let entry = LogEntry {
            timestamp: "2025-01-01T00:00:00Z".into(),
            session: "s1",
            cwd: "/tmp",
            project_dir: "",
            command: "ls",
            permission_mode: None,
            verdict: "allow",
            deny_reason: None,
            allow_rules: vec![],
            deny_rules: vec![],
            missing_rules: vec![],
        };
        let yaml = yaml_serde::to_string(&entry).unwrap();
        // Simulate what log_decision writes: "---\n{yaml}\n"
        let written = format!("---\n{yaml}\n");
        let docs = split_documents(&written);
        assert_eq!(
            docs.len(),
            1,
            "single entry should produce one doc, got: {docs:?}"
        );
        assert_eq!(extract_verdict(docs[0]), Some("allow".into()));
    }

    /// Two entries written back-to-back must split into exactly two docs.
    #[test]
    fn two_entries_roundtrip() {
        let mk = |v: &str| {
            let entry = LogEntry {
                timestamp: "2025-01-01T00:00:00Z".into(),
                session: "s1",
                cwd: "/tmp",
                project_dir: "",
                command: "ls",
                permission_mode: None,
                verdict: v,
                deny_reason: None,
                allow_rules: vec![],
                deny_rules: vec![],
                missing_rules: vec![],
            };
            let yaml = yaml_serde::to_string(&entry).unwrap();
            format!("---\n{yaml}\n")
        };
        let content = format!("{}{}", mk("allow"), mk("deny"));
        let docs = split_documents(&content);
        assert_eq!(
            docs.len(),
            2,
            "two entries should produce two docs, got: {docs:?}"
        );
        assert_eq!(extract_verdict(docs[0]), Some("allow".into()));
        assert_eq!(extract_verdict(docs[1]), Some("deny".into()));
    }

    // split_documents tests -----

    #[test]
    fn split_empty() {
        assert_eq!(split_documents(""), Vec::<&str>::new());
    }

    #[test]
    fn split_single_doc() {
        let content = "---\nverdict: allow\ncommand: ls\n\n";
        let docs = split_documents(content);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0], content);
    }

    #[test]
    fn split_multiple_docs() {
        let content = "\
---\nverdict: allow\ncommand: ls\n\n\
---\nverdict: deny\ncommand: rm\n\n\
---\nverdict: ask\ncommand: cat\n\n";
        let docs = split_documents(content);
        assert_eq!(docs.len(), 3);
        assert!(docs[0].contains("allow"));
        assert!(docs[1].contains("deny"));
        assert!(docs[2].contains("ask"));
    }

    #[test]
    fn split_no_separator() {
        let content = "just some random text\n";
        assert_eq!(split_documents(content), Vec::<&str>::new());
    }

    #[test]
    fn split_does_not_split_on_mid_line_dashes() {
        let content = "---\ncommand: 'echo ---\\nhello'\nverdict: allow\n\n";
        let docs = split_documents(content);
        assert_eq!(docs.len(), 1);
    }

    // extract_verdict tests -----

    #[test]
    fn extract_verdict_allow() {
        let doc = "---\ntimestamp: '2025-01-01T00:00:00Z'\nverdict: allow\ncommand: ls\n\n";
        assert_eq!(extract_verdict(doc), Some("allow".into()));
    }

    #[test]
    fn extract_verdict_deny() {
        let doc = "---\nverdict: deny\ncommand: rm\ndeny_reason: matched deny rule\n\n";
        assert_eq!(extract_verdict(doc), Some("deny".into()));
    }

    #[test]
    fn extract_verdict_ask() {
        let doc = "---\nverdict: ask\ncommand: cat /etc/passwd\n\n";
        assert_eq!(extract_verdict(doc), Some("ask".into()));
    }

    #[test]
    fn extract_verdict_malformed() {
        assert_eq!(extract_verdict("not valid yaml: [[["), None);
    }

    #[test]
    fn extract_verdict_empty_string() {
        let doc = "---\nverdict: ''\ncommand: ls\n\n";
        assert_eq!(extract_verdict(doc), None);
    }

    #[test]
    fn extract_verdict_without_prefix() {
        let doc = "verdict: allow\ncommand: ls\n";
        assert_eq!(extract_verdict(doc), Some("allow".into()));
    }

    #[test]
    fn extract_verdict_missing_field() {
        let doc = "---\ncommand: ls\ntimestamp: '2025-01-01'\n\n";
        assert_eq!(extract_verdict(doc), None);
    }
}
