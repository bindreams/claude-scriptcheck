use clap::ValueEnum;

/// Permission mode passed from Claude Code in the PreToolUse hook input, or
/// specified on the `claude-scriptcheck check --permission-mode` CLI flag.
///
/// Values correspond 1:1 with Claude Code's on-the-wire representation
/// (camelCase). Unknown mode strings fall back to `None` via `from_hook_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "camelCase")]
pub enum PermissionMode {
    Default,
    Plan,
    AcceptEdits,
    Auto,
    DontAsk,
    BypassPermissions,
}

impl PermissionMode {
    /// Parse a mode from the hook JSON's `permission_mode` field, accepting
    /// either camelCase (the Claude Code wire format) or kebab-case.
    ///
    /// Returns `None` if the input is `None`, an empty/whitespace string, or
    /// an unrecognized value. Unrecognized values intentionally fall through
    /// to default behavior rather than erroring — forward-compat with any
    /// future mode Claude Code adds before scriptcheck learns about it.
    pub fn from_hook_str(s: Option<&str>) -> Option<Self> {
        let trimmed = s?.trim();
        if trimmed.is_empty() {
            return None;
        }
        Self::from_str(trimmed, true).ok()
    }

    /// The camelCase wire name used in Claude Code's hook input and in the
    /// `permission_mode` field of YAML log entries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Plan => "plan",
            Self::AcceptEdits => "acceptEdits",
            Self::Auto => "auto",
            Self::DontAsk => "dontAsk",
            Self::BypassPermissions => "bypassPermissions",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_camel_case() {
        assert_eq!(
            PermissionMode::from_hook_str(Some("bypassPermissions")),
            Some(PermissionMode::BypassPermissions),
        );
        assert_eq!(
            PermissionMode::from_hook_str(Some("acceptEdits")),
            Some(PermissionMode::AcceptEdits),
        );
        assert_eq!(
            PermissionMode::from_hook_str(Some("dontAsk")),
            Some(PermissionMode::DontAsk),
        );
        assert_eq!(
            PermissionMode::from_hook_str(Some("auto")),
            Some(PermissionMode::Auto),
        );
    }

    #[test]
    fn none_input_returns_none() {
        assert_eq!(PermissionMode::from_hook_str(None), None);
    }

    #[test]
    fn empty_and_whitespace_return_none() {
        assert_eq!(PermissionMode::from_hook_str(Some("")), None);
        assert_eq!(PermissionMode::from_hook_str(Some("   ")), None);
    }

    #[test]
    fn unknown_string_returns_none() {
        assert_eq!(PermissionMode::from_hook_str(Some("future-mode")), None);
        assert_eq!(PermissionMode::from_hook_str(Some("not-a-mode")), None);
    }

    #[test]
    fn case_insensitive_parsing_for_hook_input() {
        // from_hook_str is intentionally lenient: Claude Code sends camelCase
        // exactly, but case variants from third-party wrappers are accepted.
        assert_eq!(
            PermissionMode::from_hook_str(Some("BYPASSPERMISSIONS")),
            Some(PermissionMode::BypassPermissions),
        );
        assert_eq!(
            PermissionMode::from_hook_str(Some("dontask")),
            Some(PermissionMode::DontAsk),
        );
    }
}
