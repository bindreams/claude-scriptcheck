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
