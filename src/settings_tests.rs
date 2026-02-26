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

// ─── ask rules ──────────────────────────────────────────────────────────────

#[test]
fn parse_settings_with_ask() {
    let json = r#"{"permissions": {"allow": ["Bash(ls)"], "deny": [], "ask": ["Bash(rm *)"]}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    let perms = settings.permissions.unwrap();
    assert_eq!(perms.ask, vec!["Bash(rm *)"]);
}

#[test]
fn parse_settings_ask_defaults_empty() {
    let json = r#"{"permissions": {"allow": ["Bash(ls)"], "deny": []}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    let perms = settings.permissions.unwrap();
    assert!(perms.ask.is_empty());
}

// ─── managed settings ───────────────────────────────────────────────────────

#[test]
fn parse_managed_settings() {
    let json = r#"{
        "permissions": {"allow": ["Bash(npm *)"], "deny": ["Bash(curl *)"], "ask": ["Bash(rm *)"]},
        "allowManagedPermissionRulesOnly": true
    }"#;
    let ms: ManagedSettings = serde_json::from_str(json).unwrap();
    assert!(ms.allow_managed_permission_rules_only);
    let perms = ms.permissions.unwrap();
    assert_eq!(perms.allow, vec!["Bash(npm *)"]);
    assert_eq!(perms.deny, vec!["Bash(curl *)"]);
    assert_eq!(perms.ask, vec!["Bash(rm *)"]);
}

#[test]
fn parse_managed_settings_flag_defaults_false() {
    let json = r#"{"permissions": {"allow": [], "deny": []}}"#;
    let ms: ManagedSettings = serde_json::from_str(json).unwrap();
    assert!(!ms.allow_managed_permission_rules_only);
}

#[test]
fn parse_managed_settings_no_permissions() {
    let json = r#"{"allowManagedPermissionRulesOnly": true}"#;
    let ms: ManagedSettings = serde_json::from_str(json).unwrap();
    assert!(ms.allow_managed_permission_rules_only);
    assert!(ms.permissions.is_none());
}

// ─── load_settings_from_contents ────────────────────────────────────────────

#[test]
fn merge_ask_from_multiple_files() {
    let perms = load_settings_from_contents(
        None,
        &[
            r#"{"permissions": {"allow": ["Bash(ls)"], "deny": [], "ask": ["Bash(rm *)"]}}"#,
            r#"{"permissions": {"allow": [], "deny": [], "ask": ["Bash(curl *)"]}}"#,
        ],
    );
    assert_eq!(perms.ask, vec!["Bash(rm *)", "Bash(curl *)"]);
}

#[test]
fn managed_only_discards_user_rules() {
    let perms = load_settings_from_contents(
        Some(r#"{"permissions": {"allow": ["Bash(npm *)"], "deny": ["Bash(curl *)"], "ask": []}, "allowManagedPermissionRulesOnly": true}"#),
        &[
            r#"{"permissions": {"allow": ["Bash(ls *)"], "deny": ["Bash(rm *)"], "ask": ["Bash(git *)"]}}"#,
        ],
    );
    // Only managed rules survive
    assert_eq!(perms.allow, vec!["Bash(npm *)"]);
    assert_eq!(perms.deny, vec!["Bash(curl *)"]);
    assert!(perms.ask.is_empty());
}

#[test]
fn managed_merged_when_flag_false() {
    let perms = load_settings_from_contents(
        Some(r#"{"permissions": {"allow": ["Bash(npm *)"], "deny": [], "ask": []}}"#),
        &[
            r#"{"permissions": {"allow": ["Bash(ls *)"], "deny": [], "ask": []}}"#,
        ],
    );
    assert_eq!(perms.allow, vec!["Bash(npm *)", "Bash(ls *)"]);
}

#[test]
fn managed_none_still_loads_user_rules() {
    let perms = load_settings_from_contents(
        None,
        &[
            r#"{"permissions": {"allow": ["Bash(ls *)"], "deny": [], "ask": []}}"#,
        ],
    );
    assert_eq!(perms.allow, vec!["Bash(ls *)"]);
}

// ─── resolve_rule_relative_paths ──────────────────────────────────────────────

#[test]
fn relative_read_resolved_against_base() {
    let mut rules = vec!["Read(src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/src/**)"]);
}

#[test]
fn relative_write_resolved_against_base() {
    let mut rules = vec!["Write(out/file.txt)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Write(/home/user/project/out/file.txt)"]);
}

#[test]
fn relative_edit_resolved_against_base() {
    let mut rules = vec!["Edit(src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Edit(/home/user/project/src/**)"]);
}

#[test]
fn absolute_rule_not_modified() {
    let mut rules = vec!["Read(/etc/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Read(/etc/**)"]);
}

#[test]
fn tilde_rule_not_modified() {
    let mut rules = vec!["Read(~/src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Read(~/src/**)"]);
}

#[test]
fn bash_rule_not_modified() {
    let mut rules = vec!["Bash(ls *)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Bash(ls *)"]);
}

#[test]
fn non_file_rule_not_modified() {
    let mut rules = vec!["WebSearch".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["WebSearch"]);
}

#[test]
fn dot_relative_path_resolved() {
    let mut rules = vec!["Read(./src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/./src/**)"]);
}

#[test]
fn dotdot_relative_path_resolved() {
    let mut rules = vec!["Read(../other/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/../other/**)"]);
}

#[test]
fn mixed_rules_resolved() {
    let mut rules = vec![
        "Bash(git *)".to_string(),
        "Read(src/**)".to_string(),
        "Write(/tmp/**)".to_string(),
        "Edit(~/config/**)".to_string(),
        "Read(tests/**)".to_string(),
    ];
    resolve_rule_relative_paths(&mut rules, "/project");
    assert_eq!(rules, vec![
        "Bash(git *)",
        "Read(/project/src/**)",
        "Write(/tmp/**)",
        "Edit(~/config/**)",
        "Read(/project/tests/**)",
    ]);
}
