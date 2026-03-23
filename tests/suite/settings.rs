use claude_scriptcheck::settings::*;

#[skuld::test]
fn parse_settings_json() {
    let json =
        r#"{"permissions": {"allow": ["Bash(ls)", "Read(~/src/**)"], "deny": ["Bash(rm *)"]}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    let perms = settings.permissions.unwrap();
    assert_eq!(perms.allow, vec!["Bash(ls)", "Read(~/src/**)"]);
    assert_eq!(perms.deny, vec!["Bash(rm *)"]);
}

#[skuld::test]
fn parse_settings_no_permissions() {
    let json = r#"{"model": "opus"}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    assert!(settings.permissions.is_none());
}

#[skuld::test]
fn parse_settings_empty_lists() {
    let json = r#"{"permissions": {"allow": [], "deny": []}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    let perms = settings.permissions.unwrap();
    assert!(perms.allow.is_empty());
    assert!(perms.deny.is_empty());
}

// ─── ask rules ──────────────────────────────────────────────────────────────

#[skuld::test]
fn parse_settings_with_ask() {
    let json = r#"{"permissions": {"allow": ["Bash(ls)"], "deny": [], "ask": ["Bash(rm *)"]}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    let perms = settings.permissions.unwrap();
    assert_eq!(perms.ask, vec!["Bash(rm *)"]);
}

#[skuld::test]
fn parse_settings_ask_defaults_empty() {
    let json = r#"{"permissions": {"allow": ["Bash(ls)"], "deny": []}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    let perms = settings.permissions.unwrap();
    assert!(perms.ask.is_empty());
}

// ─── managed settings ───────────────────────────────────────────────────────

#[skuld::test]
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

#[skuld::test]
fn parse_managed_settings_flag_defaults_false() {
    let json = r#"{"permissions": {"allow": [], "deny": []}}"#;
    let ms: ManagedSettings = serde_json::from_str(json).unwrap();
    assert!(!ms.allow_managed_permission_rules_only);
}

#[skuld::test]
fn parse_managed_settings_no_permissions() {
    let json = r#"{"allowManagedPermissionRulesOnly": true}"#;
    let ms: ManagedSettings = serde_json::from_str(json).unwrap();
    assert!(ms.allow_managed_permission_rules_only);
    assert!(ms.permissions.is_none());
}

// ─── load_settings_from_contents ────────────────────────────────────────────

#[skuld::test]
fn merge_ask_from_multiple_files() {
    let loaded = load_settings_from_contents(
        None,
        &[
            r#"{"permissions": {"allow": ["Bash(ls)"], "deny": [], "ask": ["Bash(rm *)"]}}"#,
            r#"{"permissions": {"allow": [], "deny": [], "ask": ["Bash(curl *)"]}}"#,
        ],
    );
    assert_eq!(loaded.permissions.ask, vec!["Bash(rm *)", "Bash(curl *)"]);
}

#[skuld::test]
fn managed_only_discards_user_rules() {
    let loaded = load_settings_from_contents(
        Some(
            r#"{"permissions": {"allow": ["Bash(npm *)"], "deny": ["Bash(curl *)"], "ask": []}, "allowManagedPermissionRulesOnly": true}"#,
        ),
        &[
            r#"{"permissions": {"allow": ["Bash(ls *)"], "deny": ["Bash(rm *)"], "ask": ["Bash(git *)"]}}"#,
        ],
    );
    // Only managed rules survive
    assert_eq!(loaded.permissions.allow, vec!["Bash(npm *)"]);
    assert_eq!(loaded.permissions.deny, vec!["Bash(curl *)"]);
    assert!(loaded.permissions.ask.is_empty());
}

#[skuld::test]
fn managed_merged_when_flag_false() {
    let loaded = load_settings_from_contents(
        Some(r#"{"permissions": {"allow": ["Bash(npm *)"], "deny": [], "ask": []}}"#),
        &[r#"{"permissions": {"allow": ["Bash(ls *)"], "deny": [], "ask": []}}"#],
    );
    assert_eq!(loaded.permissions.allow, vec!["Bash(npm *)", "Bash(ls *)"]);
}

#[skuld::test]
fn managed_none_still_loads_user_rules() {
    let loaded = load_settings_from_contents(
        None,
        &[r#"{"permissions": {"allow": ["Bash(ls *)"], "deny": [], "ask": []}}"#],
    );
    assert_eq!(loaded.permissions.allow, vec!["Bash(ls *)"]);
}

// ─── additionalDirectories ───────────────────────────────────────────────────

#[skuld::test]
fn parse_additional_directories() {
    let json = r#"{"additionalDirectories": ["/home/user/other", "~/Desktop"]}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    assert_eq!(
        settings.additional_directories,
        vec!["/home/user/other", "~/Desktop"]
    );
}

#[skuld::test]
fn additional_directories_defaults_empty() {
    let json = r#"{"permissions": {"allow": [], "deny": []}}"#;
    let settings: Settings = serde_json::from_str(json).unwrap();
    assert!(settings.additional_directories.is_empty());
}

#[skuld::test]
fn additional_directories_merged_from_contents() {
    let loaded = load_settings_from_contents(
        None,
        &[
            r#"{"additionalDirectories": ["/dir1"]}"#,
            r#"{"additionalDirectories": ["/dir2", "/dir3"]}"#,
        ],
    );
    assert_eq!(
        loaded.additional_directories,
        vec!["/dir1", "/dir2", "/dir3"]
    );
}

// ─── resolve_rule_relative_paths (cwd == project_root) ──────────────────────

#[skuld::test]
fn relative_read_resolved_against_cwd() {
    let mut rules = vec!["Read(src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/src/**)"]);
}

#[skuld::test]
fn relative_write_resolved_against_cwd() {
    let mut rules = vec!["Write(out/file.txt)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Write(/home/user/project/out/file.txt)"]);
}

#[skuld::test]
fn relative_edit_resolved_against_cwd() {
    let mut rules = vec!["Edit(src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Edit(/home/user/project/src/**)"]);
}

#[skuld::test]
fn single_slash_resolved_against_project_root() {
    let mut rules = vec!["Read(/etc/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/etc/**)"]);
}

#[skuld::test]
fn tilde_rule_not_modified() {
    let mut rules = vec!["Read(~/src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(~/src/**)"]);
}

#[skuld::test]
fn bash_rule_not_modified() {
    let mut rules = vec!["Bash(ls *)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Bash(ls *)"]);
}

#[skuld::test]
fn non_file_rule_not_modified() {
    let mut rules = vec!["WebSearch".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["WebSearch"]);
}

#[skuld::test]
fn dot_relative_path_resolved() {
    let mut rules = vec!["Read(./src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/./src/**)"]);
}

#[skuld::test]
fn dotdot_relative_path_resolved() {
    let mut rules = vec!["Read(../other/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/../other/**)"]);
}

#[skuld::test]
fn mixed_rules_resolved() {
    let mut rules = vec![
        "Bash(git *)".to_string(),
        "Read(src/**)".to_string(),
        "Write(/tmp/**)".to_string(),
        "Edit(~/config/**)".to_string(),
        "Read(tests/**)".to_string(),
    ];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(
        rules,
        vec![
            "Bash(git *)",
            "Read(/project/src/**)",
            "Write(/project/tmp/**)",
            "Edit(~/config/**)",
            "Read(/project/tests/**)",
        ]
    );
}

// ─── double-slash (absolute filesystem) paths ────────────────────────────────

#[skuld::test]
fn double_slash_absolute_path() {
    let mut rules = vec!["Read(//etc/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(/etc/**)"]);
}

#[skuld::test]
fn double_slash_root() {
    let mut rules = vec!["Read(//)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(rules, vec!["Read(/)"]);
}

#[skuld::test]
fn double_slash_with_nested_path() {
    let mut rules = vec!["Write(//var/log/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(rules, vec!["Write(/var/log/**)"]);
}

// ─── single-slash (project-root-relative) paths ─────────────────────────────

#[skuld::test]
fn single_slash_read_project_root_relative() {
    let mut rules = vec!["Read(/src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(/home/user/project/src/**)"]);
}

#[skuld::test]
fn single_slash_write_project_root_relative() {
    let mut rules = vec!["Write(/out/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(rules, vec!["Write(/project/out/**)"]);
}

#[skuld::test]
fn single_slash_edit_project_root_relative() {
    let mut rules = vec!["Edit(/config/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(rules, vec!["Edit(/project/config/**)"]);
}

// ─── cwd != project_root ────────────────────────────────────────────────────

#[skuld::test]
fn cwd_differs_from_project_root() {
    let mut rules = vec![
        "Read(src/**)".to_string(),    // bare → cwd-relative
        "Read(/src/**)".to_string(),   // /path → project-root-relative
        "Read(//etc/**)".to_string(),  // //path → absolute
        "Read(~/docs/**)".to_string(), // ~/path → home-relative
    ];
    resolve_rule_relative_paths(
        &mut rules,
        "/home/user/project/subdir", // cwd (cd'd into subdir)
        "/home/user/project",        // project root
    );
    assert_eq!(
        rules,
        vec![
            "Read(/home/user/project/subdir/src/**)", // resolved against cwd
            "Read(/home/user/project/src/**)",        // resolved against project root
            "Read(/etc/**)",                          // absolute
            "Read(~/docs/**)",                        // tilde, untouched
        ]
    );
}

// ─── all four tiers in one test ──────────────────────────────────────────────

#[skuld::test]
fn mixed_rules_all_four_tiers() {
    let mut rules = vec![
        "Read(//etc/passwd)".to_string(), // absolute
        "Read(~/src/**)".to_string(),     // home-relative
        "Read(/src/**)".to_string(),      // project-root-relative
        "Read(src/**)".to_string(),       // CWD-relative
        "Write(./out/**)".to_string(),    // CWD-relative (dot form)
    ];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(
        rules,
        vec![
            "Read(/etc/passwd)",
            "Read(~/src/**)",
            "Read(/home/user/project/src/**)",
            "Read(/home/user/project/src/**)",
            "Write(/home/user/project/./out/**)",
        ]
    );
}

// Windows paths =======================================================================================================

#[skuld::test]
fn double_slash_windows_drive_letter() {
    let mut rules = vec!["Read(//C:/Users/foo/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(rules, vec!["Read(C:/Users/foo/**)"]);
}

#[skuld::test]
fn bare_windows_absolute_path_unchanged() {
    let mut rules = vec!["Write(C:/Users/foo/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/project", "/project");
    assert_eq!(rules, vec!["Write(C:/Users/foo/**)"]);
}

#[skuld::test]
fn relative_path_with_windows_cwd() {
    let mut rules = vec!["Read(src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "C:/Users/foo/project", "C:/Users/foo/project");
    assert_eq!(rules, vec!["Read(C:/Users/foo/project/src/**)"]);
}

#[skuld::test]
fn single_slash_with_windows_project_root() {
    let mut rules = vec!["Read(/src/**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "C:/Users/foo/project", "C:/Users/foo/project");
    assert_eq!(rules, vec!["Read(C:/Users/foo/project/src/**)"]);
}
