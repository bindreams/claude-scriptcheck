use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct Settings {
    permissions: Option<PermissionsJson>,
}

#[derive(Deserialize)]
struct PermissionsJson {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Default, Clone)]
pub struct Permissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

pub fn load_settings(cwd: &str) -> Permissions {
    let mut merged = Permissions::default();

    // Global settings
    if let Some(home) = dirs::home_dir() {
        let global = home.join(".claude/settings.json");
        merge_from(&global, &mut merged);
    }

    // Project-level settings
    let project = Path::new(cwd).join(".claude/settings.json");
    merge_from(&project, &mut merged);

    // Project-level local settings
    let local = Path::new(cwd).join(".claude/settings.local.json");
    merge_from(&local, &mut merged);

    merged
}

fn merge_from(path: &Path, merged: &mut Permissions) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(settings) = serde_json::from_str::<Settings>(&content) else {
        return;
    };
    if let Some(perms) = settings.permissions {
        merged.allow.extend(perms.allow);
        merged.deny.extend(perms.deny);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_settings_json() {
        let json = r#"{"permissions": {"allow": ["Bash(ls)", "Read(~/src/**)"], "deny": ["Bash(rm *)"]}}"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        let perms = settings.permissions.unwrap();
        assert_eq!(perms.allow, vec!["Bash(ls)", "Read(~/src/**)"]);
        assert_eq!(perms.deny, vec!["Bash(rm *)"]);
    }

    #[test]
    fn parse_settings_no_permissions() {
        let json = r#"{"model": "opus"}"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        assert!(settings.permissions.is_none());
    }

    #[test]
    fn parse_settings_empty_lists() {
        let json = r#"{"permissions": {"allow": [], "deny": []}}"#;
        let settings: Settings = serde_json::from_str(json).unwrap();
        let perms = settings.permissions.unwrap();
        assert!(perms.allow.is_empty());
        assert!(perms.deny.is_empty());
    }
}
