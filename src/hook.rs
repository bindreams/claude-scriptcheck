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
}

#[derive(Deserialize)]
pub struct ToolInput {
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl HookOutput {
    pub fn new(decision: &str, reason: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason.to_string(),
            },
        }
    }
}
