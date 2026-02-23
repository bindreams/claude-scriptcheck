use crate::settings::*;

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
