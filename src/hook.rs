use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct HookInput {
    #[allow(dead_code)]
    pub session_id: String,
    pub cwd: String,
    #[allow(dead_code)]
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: ToolInput,
    #[allow(dead_code)]
    pub tool_use_id: String,
    /// Permission mode from Claude Code (e.g. "default", "acceptEdits", "bypassPermissions").
    /// None if the field is absent (older Claude Code versions).
    #[serde(default, alias = "permissionMode")]
    pub permission_mode: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn permission_mode_snake_case() {
        let json = r#"{
            "session_id": "s", "cwd": "/", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t",
            "permission_mode": "acceptEdits"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permission_mode.as_deref(), Some("acceptEdits"));
    }

    #[test]
    fn permission_mode_camel_case_alias() {
        let json = r#"{
            "session_id": "s", "cwd": "/", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t",
            "permissionMode": "acceptEdits"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permission_mode.as_deref(), Some("acceptEdits"));
    }

    #[test]
    fn permission_mode_absent() {
        let json = r#"{
            "session_id": "s", "cwd": "/", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permission_mode, None);
    }

    #[test]
    fn claude_hook_output_serializes_permission_reason() {
        let json = serde_json::to_value(ClaudeHookOutput::new("allow", "ok")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": "ok"
                }
            })
        );
    }

    #[test]
    fn codex_allow_output_serializes_updated_input() {
        let json = serde_json::to_value(CodexHookOutput::allow_command("ls -la")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {
                        "command": "ls -la"
                    }
                }
            })
        );
    }

    #[test]
    fn codex_allow_output_serializes_additional_context_when_present() {
        let json = serde_json::to_value(CodexHookOutput::allow_command_with_context(
            "ls -la",
            Some("ok"),
        ))
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {
                        "command": "ls -la"
                    },
                    "additionalContext": "ok"
                }
            })
        );
    }

    #[test]
    fn codex_deny_output_serializes_permission_reason() {
        let json = serde_json::to_value(CodexHookOutput::deny("blocked")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "blocked"
                }
            })
        );
    }
}

#[derive(Deserialize)]
pub struct ToolInput {
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct ClaudeHookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: ClaudeHookSpecificOutput,
}

pub type HookOutput = ClaudeHookOutput;

#[derive(Serialize)]
pub struct ClaudeHookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

pub type HookSpecificOutput = ClaudeHookSpecificOutput;

impl ClaudeHookOutput {
    pub fn new(decision: &str, reason: &str) -> Self {
        Self {
            hook_specific_output: ClaudeHookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason.to_string(),
            },
        }
    }
}

#[derive(Serialize)]
pub struct CodexHookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: CodexHookSpecificOutput,
}

#[derive(Serialize)]
pub struct CodexHookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<CodexUpdatedInput>,
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

#[derive(Serialize)]
pub struct CodexUpdatedInput {
    pub command: String,
}

impl CodexHookOutput {
    pub fn allow_command(command: &str) -> Self {
        Self::allow_command_with_context(command, None)
    }

    pub fn allow_command_with_context(command: &str, additional_context: Option<&str>) -> Self {
        Self {
            hook_specific_output: CodexHookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: None,
                updated_input: Some(CodexUpdatedInput {
                    command: command.to_string(),
                }),
                additional_context: additional_context.map(ToString::to_string),
            },
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            hook_specific_output: CodexHookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.to_string()),
                updated_input: None,
                additional_context: None,
            },
        }
    }
}
