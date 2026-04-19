//! Test-isolation env-var hooks.
//!
//! Provides indirection around `dirs::home_dir()` and the log path so integration
//! tests can redirect both to temp locations without writing to the developer's
//! real `~/.claude/settings.json` or log file.
//!
//! On Windows `dirs::home_dir()` calls `SHGetKnownFolderPath(FOLDERID_Profile)`,
//! which ignores `HOME`/`USERPROFILE`/`HOMEDRIVE`+`HOMEPATH` env vars — so the
//! test helper's `HOME` override cannot isolate on Windows without help.

use std::ffi::OsString;
use std::path::PathBuf;

/// Home directory used by the hook dispatch path (settings loader, tilde expansion
/// in rule and file-access paths). Respects `CLAUDE_SCRIPTCHECK_HOOK_HOME` for tests,
/// otherwise falls back to `dirs::home_dir()`.
///
/// Does *not* affect `cli::install`/`uninstall`/`upgrade`, which always target the
/// real home.
pub fn hook_home() -> Option<PathBuf> {
    hook_home_with(|k| std::env::var_os(k))
}

fn hook_home_with<F: Fn(&str) -> Option<OsString>>(get_env: F) -> Option<PathBuf> {
    match get_env("CLAUDE_SCRIPTCHECK_HOOK_HOME") {
        Some(s) if !is_blank(&s) => Some(PathBuf::from(s)),
        _ => dirs::home_dir(),
    }
}

/// Log-path override. Respected by both writers (`log_decision`) and readers
/// (`cli::log`, `cli::log-path`) so they stay in agreement.
pub fn log_path_override() -> Option<PathBuf> {
    log_path_override_with(|k| std::env::var_os(k))
}

fn log_path_override_with<F: Fn(&str) -> Option<OsString>>(get_env: F) -> Option<PathBuf> {
    match get_env("CLAUDE_SCRIPTCHECK_LOG_PATH") {
        Some(s) if !is_blank(&s) => Some(PathBuf::from(s)),
        _ => None,
    }
}

/// Treat empty or whitespace-only `OsString` values as unset. Whitespace
/// detection is UTF-8 lossy (non-UTF-8 bytes are considered non-whitespace),
/// which is the right default for path-like env vars.
fn is_blank(s: &OsString) -> bool {
    match s.to_str() {
        Some(t) => t.trim().is_empty(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_reader(key: &str, value: Option<&str>) -> impl Fn(&str) -> Option<OsString> {
        let expected_key = key.to_string();
        let value = value.map(OsString::from);
        move |k: &str| {
            if k == expected_key {
                value.clone()
            } else {
                None
            }
        }
    }

    #[test]
    fn hook_home_unset_falls_back_to_dirs_home() {
        let result = hook_home_with(env_reader("CLAUDE_SCRIPTCHECK_HOOK_HOME", None));
        assert_eq!(result, dirs::home_dir());
    }

    #[test]
    fn hook_home_set_returns_override() {
        let result = hook_home_with(env_reader(
            "CLAUDE_SCRIPTCHECK_HOOK_HOME",
            Some("C:/some/path"),
        ));
        assert_eq!(result, Some(PathBuf::from("C:/some/path")));
    }

    #[test]
    fn hook_home_empty_string_falls_back_to_dirs_home() {
        let result = hook_home_with(env_reader("CLAUDE_SCRIPTCHECK_HOOK_HOME", Some("")));
        assert_eq!(result, dirs::home_dir());
    }

    #[test]
    fn hook_home_whitespace_only_falls_back_to_dirs_home() {
        let result = hook_home_with(env_reader("CLAUDE_SCRIPTCHECK_HOOK_HOME", Some("   ")));
        assert_eq!(result, dirs::home_dir());
    }

    #[test]
    fn log_path_override_unset_returns_none() {
        let result = log_path_override_with(env_reader("CLAUDE_SCRIPTCHECK_LOG_PATH", None));
        assert_eq!(result, None);
    }

    #[test]
    fn log_path_override_set_returns_override() {
        let result = log_path_override_with(env_reader(
            "CLAUDE_SCRIPTCHECK_LOG_PATH",
            Some("/tmp/custom.log"),
        ));
        assert_eq!(result, Some(PathBuf::from("/tmp/custom.log")));
    }

    #[test]
    fn log_path_override_empty_string_returns_none() {
        let result = log_path_override_with(env_reader("CLAUDE_SCRIPTCHECK_LOG_PATH", Some("")));
        assert_eq!(result, None);
    }

    #[test]
    fn log_path_override_whitespace_only_returns_none() {
        let result = log_path_override_with(env_reader(
            "CLAUDE_SCRIPTCHECK_LOG_PATH",
            Some("   "),
        ));
        assert_eq!(result, None);
    }
}
