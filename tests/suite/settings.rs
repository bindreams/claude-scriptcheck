use claude_scriptcheck::codex_settings::*;
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

// ─── Codex TOML settings ─────────────────────────────────────────────────────

#[skuld::test]
fn codex_settings_merge_system_user_and_trusted_project_layers() {
    let loaded = load_codex_settings_from_contents(
        Some(
            r#"
            [scriptcheck.permissions]
            allow = ["Bash(system-allow *)"]
            deny = ["Bash(system-deny *)"]
            "#,
        ),
        Some(
            r#"
            project_root_markers = [".git", ".jj"]

            [projects."/repo"]
            trust_level = "trusted"

            [scriptcheck.permissions]
            allow = ["Bash(user-allow *)"]
            ask = ["Bash(user-ask *)"]
            additional_directories = ["/user/dir"]
            "#,
        ),
        &[
            CodexConfigLayer {
                path: "/repo/.codex/config.toml",
                content: r#"
                    [scriptcheck.permissions]
                    allow = ["Bash(root-allow *)"]
                "#,
            },
            CodexConfigLayer {
                path: "/repo/apps/.codex/config.toml",
                content: r#"
                    [scriptcheck.permissions]
                    deny = ["Bash(app-deny *)"]
                    ask = ["Bash(app-ask *)"]
                    additional_directories = ["/app/dir"]
                "#,
            },
        ],
        "/repo/apps",
    );

    // Codex override-merge: the highest-precedence layer that SETS a field wins
    // (array-replace), unlike Claude's additive merge. Layers fold low->high:
    // system, user, /repo, /repo/apps. So allow's last setter is /repo
    // (root-allow); deny/ask/additional_directories' last setter is /repo/apps.
    assert_eq!(loaded.permissions.allow, vec!["Bash(root-allow *)"]);
    assert_eq!(loaded.permissions.deny, vec!["Bash(app-deny *)"]);
    assert_eq!(loaded.permissions.ask, vec!["Bash(app-ask *)"]);
    assert_eq!(loaded.permissions.additional_directories, vec!["/app/dir"]);
}

#[skuld::test]
fn codex_settings_skip_untrusted_project_layers() {
    let loaded = load_codex_settings_from_contents(
        None,
        Some(
            r#"
            [projects."/repo"]
            trust_level = "untrusted"

            [scriptcheck.permissions]
            allow = ["Bash(user-allow *)"]
            "#,
        ),
        &[CodexConfigLayer {
            path: "/repo/.codex/config.toml",
            content: r#"
                [scriptcheck.permissions]
                allow = ["Bash(project-allow *)"]
                deny = ["Bash(project-deny *)"]
            "#,
        }],
        "/repo",
    );

    assert_eq!(loaded.permissions.allow, vec!["Bash(user-allow *)"]);
    assert!(loaded.permissions.deny.is_empty());
}

#[skuld::test]
fn codex_override_merge_explicit_empty_clears_lower_layer() {
    // Codex override-merge: a trusted project layer setting `deny = []` REPLACES
    // (clears) the user-level deny rules. This is faithful to Codex and is
    // security-relevant — trusting a project grants it power over your deny list.
    let loaded = load_codex_settings_from_contents(
        None,
        Some(
            r#"
            [projects."/repo"]
            trust_level = "trusted"

            [scriptcheck.permissions]
            deny = ["Bash(rm *)"]
            "#,
        ),
        &[CodexConfigLayer {
            path: "/repo/.codex/config.toml",
            content: r#"
                [scriptcheck.permissions]
                deny = []
            "#,
        }],
        "/repo",
    );
    assert!(
        loaded.permissions.deny.is_empty(),
        "an explicit empty deny in a trusted project layer should clear the user's deny rules"
    );
}

#[skuld::test]
fn codex_worktree_is_trusted_via_main_repo() {
    // A git worktree whose own path is NOT in `[projects]`, but whose main repo
    // IS trusted, loads its project layer via the repo-root trust tier.
    let tmp = tempfile::tempdir().unwrap();
    let main = tmp.path().join("main");
    std::fs::create_dir_all(main.join(".git").join("worktrees").join("wt")).unwrap();
    let wt = tmp.path().join("wt");
    std::fs::create_dir_all(wt.join(".codex")).unwrap();
    let main_fwd = main.to_string_lossy().replace('\\', "/");
    std::fs::write(
        wt.join(".git"),
        format!("gitdir: {main_fwd}/.git/worktrees/wt\n"),
    )
    .unwrap();

    let user = format!("[projects.\"{main_fwd}\"]\ntrust_level = \"trusted\"\n");
    let wt_fwd = wt.to_string_lossy().replace('\\', "/");
    let layer_path = format!("{wt_fwd}/.codex/config.toml");
    let loaded = load_codex_settings_from_contents(
        None,
        Some(&user),
        &[CodexConfigLayer {
            path: &layer_path,
            content: r#"
                [scriptcheck.permissions]
                allow = ["Bash(worktree-allow *)"]
            "#,
        }],
        &wt_fwd,
    );
    assert_eq!(
        loaded.permissions.allow,
        vec!["Bash(worktree-allow *)"],
        "worktree should load its project layer via the trusted main repo"
    );
}

#[skuld::test]
fn codex_settings_trust_lookup_matches_canonicalized_project_paths() {
    let temp = std::env::temp_dir().join(format!(
        "claude-scriptcheck-codex-trust-canonical-{}",
        std::process::id()
    ));
    let repo = temp.join("repo");
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(repo.join(".git")).unwrap();

    let repo_display = claude_scriptcheck::path_util::normalize_separators(&repo.to_string_lossy());
    let repo_canonical = claude_scriptcheck::path_util::normalize_separators(
        &std::fs::canonicalize(&repo).unwrap().to_string_lossy(),
    );

    let loaded = load_codex_settings_from_contents(
        None,
        Some(&format!(
            r#"
            [projects."{repo_display}"]
            trust_level = "trusted"
            "#
        )),
        &[CodexConfigLayer {
            path: &format!("{repo_canonical}/.codex/config.toml"),
            content: r#"
                [scriptcheck.permissions]
                allow = ["Bash(project-allow *)"]
            "#,
        }],
        &repo_canonical,
    );

    assert_eq!(loaded.permissions.allow, vec!["Bash(project-allow *)"]);

    let _ = std::fs::remove_dir_all(&temp);
}

#[skuld::test]
fn codex_project_root_uses_configured_markers() {
    let root = find_codex_project_root_from_paths(
        "/repo/work/service/src",
        &["/repo/.jj", "/repo/work/.codex/config.toml"],
        &[".git".to_string(), ".jj".to_string()],
    );
    assert_eq!(root.as_deref(), Some("/repo"));
}

#[skuld::test]
fn codex_project_root_prefers_nearest_marker() {
    // With nested markers, Codex's find_project_root returns the NEAREST ancestor
    // marker (walking up from cwd, first hit wins), not the farthest.
    let root = find_codex_project_root_from_paths(
        "/repo/app/src",
        &["/repo/.git", "/repo/app/.git"],
        &[".git".to_string()],
    );
    assert_eq!(root.as_deref(), Some("/repo/app"));
}

#[skuld::test]
fn codex_project_root_markers_empty_uses_cwd() {
    let root = find_codex_project_root_from_paths("/repo/work/service", &[], &[]);
    assert_eq!(root.as_deref(), Some("/repo/work/service"));
}

#[skuld::test]
fn install_codex_hooks_into_toml_adds_matchers_and_enables_features_hooks() {
    let output = install_codex_hooks_into_toml(
        r#"# top comment
[features]
other = true
"#,
        "/tmp/claude-scriptcheck --agent codex",
        false,
    )
    .unwrap();

    assert!(output.contains("# top comment"));
    assert!(output.contains("[features]"));
    assert!(output.contains("other = true"));
    assert!(output.contains("hooks = true"));
    assert!(output.contains("matcher = \"^Bash$\""));
    assert!(output.contains("matcher = \"^apply_patch$\""));
    assert_eq!(output.matches("type = \"command\"").count(), 2);
    assert_eq!(
        output
            .matches("command = \"/tmp/claude-scriptcheck --agent codex\"")
            .count(),
        2
    );
}

#[skuld::test]
fn install_codex_hooks_into_toml_preserves_foreign_hooks_and_non_command_handlers() {
    let input = r#"# lead
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/bin/other-hook"

[[hooks.PreToolUse.hooks]]
type = "webhook"
url = "https://example.test/hook"

[hooks.state]
keep = "yes"
"#;

    let output =
        install_codex_hooks_into_toml(input, "/tmp/claude-scriptcheck --agent=codex", false)
            .unwrap();

    assert!(output.contains("# lead"));
    assert!(output.contains("command = \"/usr/bin/other-hook\""));
    assert!(output.contains("type = \"webhook\""));
    assert!(output.contains("url = \"https://example.test/hook\""));
    assert!(output.contains("[hooks.state]"));
    assert!(output.contains("keep = \"yes\""));
    assert!(output.contains("matcher = \"^Bash$\""));
    assert!(output.contains("matcher = \"^apply_patch$\""));
    assert_eq!(
        output
            .matches("command = \"/tmp/claude-scriptcheck --agent=codex\"")
            .count(),
        2
    );
}

#[skuld::test]
fn install_codex_hooks_into_toml_replaces_owned_bare_handler_instead_of_duplicating() {
    let input = r#"[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "claude-scriptcheck --agent codex"
"#;

    let output =
        install_codex_hooks_into_toml(input, "/new/path/claude-scriptcheck --agent codex", false)
            .unwrap();

    assert!(!output.contains(r#"command = "claude-scriptcheck --agent codex""#));
    assert_eq!(
        output
            .matches("command = \"/new/path/claude-scriptcheck --agent codex\"")
            .count(),
        2
    );
}

#[skuld::test]
fn install_codex_hooks_into_toml_preserves_foreign_scriptcheck_binary_paths() {
    let input = r#"[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/foreign/bin/claude-scriptcheck --agent codex"
"#;

    let output =
        install_codex_hooks_into_toml(input, "/owned/bin/claude-scriptcheck --agent codex", false)
            .unwrap();

    assert!(output.contains(r#"command = "/foreign/bin/claude-scriptcheck --agent codex""#));
    assert!(output.contains(r#"command = "/owned/bin/claude-scriptcheck --agent codex""#));
}

#[skuld::test]
fn install_codex_hooks_into_toml_is_idempotent() {
    let once =
        install_codex_hooks_into_toml("", "/tmp/claude-scriptcheck --agent codex", false).unwrap();
    let twice =
        install_codex_hooks_into_toml(&once, "/tmp/claude-scriptcheck --agent codex", false)
            .unwrap();

    assert_eq!(twice, once);
}

#[skuld::test]
fn install_codex_hooks_into_toml_fails_when_hooks_json_exists() {
    let error = install_codex_hooks_into_toml("", "/tmp/claude-scriptcheck --agent codex", true)
        .unwrap_err();

    assert_eq!(error, CodexTomlMutationError::HooksJsonExists);
}

#[skuld::test]
fn install_codex_hooks_into_toml_rejects_legacy_command_without_codex_agent() {
    let error = install_codex_hooks_into_toml("", "/tmp/claude-scriptcheck", false).unwrap_err();

    assert_eq!(error, CodexTomlMutationError::InvalidInstallCommand);
}

#[skuld::test]
fn install_codex_hooks_into_toml_rejects_command_with_extra_args() {
    let error =
        install_codex_hooks_into_toml("", "/tmp/claude-scriptcheck --agent codex --verbose", false)
            .unwrap_err();

    assert_eq!(error, CodexTomlMutationError::InvalidInstallCommand);
}

#[skuld::test]
fn install_codex_hooks_into_toml_fails_when_features_is_not_a_table() {
    let error = install_codex_hooks_into_toml(
        r#"features = "broken""#,
        "/tmp/claude-scriptcheck --agent codex",
        false,
    )
    .unwrap_err();

    assert_eq!(
        error,
        CodexTomlMutationError::UnexpectedTomlType("features".to_string())
    );
}

#[skuld::test]
fn install_codex_hooks_into_toml_fails_when_hooks_is_not_a_table() {
    let error = install_codex_hooks_into_toml(
        r#"hooks = "broken""#,
        "/tmp/claude-scriptcheck --agent codex",
        false,
    )
    .unwrap_err();

    assert_eq!(
        error,
        CodexTomlMutationError::UnexpectedTomlType("hooks".to_string())
    );
}

#[skuld::test]
fn install_codex_hooks_into_toml_fails_when_pretooluse_is_not_an_array() {
    let error = install_codex_hooks_into_toml(
        r#"[hooks]
PreToolUse = "broken"
"#,
        "/tmp/claude-scriptcheck --agent codex",
        false,
    )
    .unwrap_err();

    assert_eq!(
        error,
        CodexTomlMutationError::UnexpectedTomlType("hooks.PreToolUse".to_string())
    );
}

#[skuld::test]
fn uninstall_codex_hooks_from_toml_removes_only_owned_codex_handlers() {
    let input = r#"[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/tmp/claude-scriptcheck --agent codex"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/tmp/claude-scriptcheck"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/bin/other-hook"

[[hooks.PreToolUse.hooks]]
type = "webhook"
url = "https://example.test/hook"

[[hooks.PreToolUse]]
matcher = "^apply_patch$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/tmp/claude-scriptcheck --agent=codex"

[hooks.state]
keep = "yes"
"#;

    let output = uninstall_codex_hooks_from_toml(input, "/tmp/claude-scriptcheck", false).unwrap();

    assert!(!output.contains("/tmp/claude-scriptcheck --agent codex"));
    assert!(!output.contains("/tmp/claude-scriptcheck --agent=codex"));
    assert!(output.contains("command = \"/tmp/claude-scriptcheck\""));
    assert!(output.contains("command = \"/usr/bin/other-hook\""));
    assert!(output.contains("type = \"webhook\""));
    assert!(output.contains("[hooks.state]"));
    assert!(output.contains("keep = \"yes\""));
}

#[skuld::test]
fn uninstall_codex_hooks_from_toml_removes_empty_matcher_entries_only() {
    let input = r#"[[hooks.PreToolUse]]
matcher = "^apply_patch$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/tmp/claude-scriptcheck --agent codex"

[hooks.state]
keep = "yes"
"#;

    let output = uninstall_codex_hooks_from_toml(input, "/tmp/claude-scriptcheck", false).unwrap();

    assert!(!output.contains("matcher = \"^apply_patch$\""));
    assert!(output.contains("[hooks.state]"));
    assert!(output.contains("keep = \"yes\""));
}

#[skuld::test]
fn uninstall_codex_hooks_from_toml_preserves_foreign_scriptcheck_binary_paths() {
    let input = r#"[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/foreign/bin/claude-scriptcheck --agent codex"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/owned/bin/claude-scriptcheck --agent codex"
"#;

    let output =
        uninstall_codex_hooks_from_toml(input, "/owned/bin/claude-scriptcheck", false).unwrap();

    assert!(output.contains(r#"command = "/foreign/bin/claude-scriptcheck --agent codex""#));
    assert!(!output.contains(r#"command = "/owned/bin/claude-scriptcheck --agent codex""#));
}

#[skuld::test]
fn uninstall_codex_hooks_from_toml_is_idempotent() {
    let once = uninstall_codex_hooks_from_toml(
        r#"[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/tmp/claude-scriptcheck --agent codex"
"#,
        "/tmp/claude-scriptcheck",
        false,
    )
    .unwrap();
    let twice = uninstall_codex_hooks_from_toml(&once, "/tmp/claude-scriptcheck", false).unwrap();

    assert_eq!(twice, once);
}

#[skuld::test]
fn uninstall_codex_hooks_from_toml_fails_when_hooks_json_exists() {
    let error = uninstall_codex_hooks_from_toml("", "/tmp/claude-scriptcheck", true).unwrap_err();

    assert_eq!(error, CodexTomlMutationError::HooksJsonExists);
}

// ─── additionalDirectories ───────────────────────────────────────────────────

#[skuld::test]
fn additional_directories_nested_in_permissions() {
    let json = r#"{"permissions": {"allow": [], "additionalDirectories": ["/extra"]}}"#;
    let loaded = load_settings_from_contents(None, &[json]);
    assert_eq!(loaded.permissions.additional_directories, vec!["/extra"]);
}

#[skuld::test]
fn additional_directories_defaults_empty() {
    let json = r#"{"permissions": {"allow": [], "deny": []}}"#;
    let loaded = load_settings_from_contents(None, &[json]);
    assert!(loaded.permissions.additional_directories.is_empty());
}

#[skuld::test]
fn additional_directories_merged_across_files() {
    let loaded = load_settings_from_contents(
        None,
        &[
            r#"{"permissions": {"allow": [], "additionalDirectories": ["/dir1"]}}"#,
            r#"{"permissions": {"allow": [], "additionalDirectories": ["/dir2"]}}"#,
        ],
    );
    assert_eq!(
        loaded.permissions.additional_directories,
        vec!["/dir1", "/dir2"]
    );
}

#[skuld::test]
fn managed_only_discards_additional_directories() {
    let loaded = load_settings_from_contents(
        Some(r#"{"permissions": {"allow": ["Bash(*)"]}, "allowManagedPermissionRulesOnly": true}"#),
        &[r#"{"permissions": {"allow": [], "additionalDirectories": ["/user/dir"]}}"#],
    );
    assert!(loaded.permissions.additional_directories.is_empty());
}

#[skuld::test]
fn managed_settings_additional_directories_propagated() {
    let loaded = load_settings_from_contents(
        Some(
            r#"{"permissions": {"allow": ["Bash(*)"], "additionalDirectories": ["/managed/dir"]}}"#,
        ),
        &[],
    );
    assert_eq!(
        loaded.permissions.additional_directories,
        vec!["/managed/dir"]
    );
}

#[skuld::test]
fn top_level_additional_directories_ignored() {
    let json = r#"{"additionalDirectories": ["/wrong-place"]}"#;
    let loaded = load_settings_from_contents(None, &[json]);
    assert!(
        loaded.permissions.additional_directories.is_empty(),
        "top-level additionalDirectories should be ignored (must be inside permissions)"
    );
}

// ─── Schema-conformance fixture ─────────────────────────────────────────────

fn validate_settings_against_schema(json: &str) {
    let schema_str = include_str!("../schemas/claude-code-settings.schema.json");
    let schema: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    let instance: serde_json::Value = serde_json::from_str(json).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<_> = validator.iter_errors(&instance).collect();
    assert!(
        errors.is_empty(),
        "settings fixture does not pass Claude Code schema:\n{}",
        errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[skuld::test]
fn settings_struct_matches_claude_code_schema() {
    // Fixture mirrors Claude Code's actual settings.json format.
    // Source of truth: https://json.schemastore.org/claude-code-settings.json
    let json = r#"{
        "permissions": {
            "additionalDirectories": ["~/src", "~/Desktop"],
            "allow": ["Read", "Bash(ls *)"],
            "deny": ["Read(~/.secrets)"],
            "ask": []
        }
    }"#;

    // Write-side: fixture must be valid per the official schema
    validate_settings_against_schema(json);

    // Read-side: our structs must capture all fields
    let loaded = load_settings_from_contents(None, &[json]);
    assert_eq!(
        loaded.permissions.additional_directories,
        vec!["~/src", "~/Desktop"]
    );
    assert_eq!(loaded.permissions.allow, vec!["Read", "Bash(ls *)"]);
    assert_eq!(loaded.permissions.deny, vec!["Read(~/.secrets)"]);
    assert!(loaded.permissions.ask.is_empty());
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

// ─── B1/B2: separator normalization before prefix dispatch ────────────────────

#[skuld::test]
fn backslash_absolute_filesystem_marker() {
    // B1: user writes `\\C:\...` intending Claude's `//abs` absolute-path marker.
    // Without separator normalization on `inner`, `strip_prefix("//")` fails on the
    // backslashes and the rule falls through to `is_absolute` (leading `\`), which
    // returns it unchanged — the project-root prefix step never runs, but neither
    // does the `//`→absolute-normalization step. Expected behavior: treat as absolute.
    let mut rules = vec!["Read(\\\\C:\\Users\\alice\\**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Read(C:/Users/alice/**)"]);
}

#[skuld::test]
fn backslash_project_root_relative() {
    // B2: user writes `\project\src` (single backslash-prefixed, intent: project-root-relative).
    // Without separator normalization, the leading `\` makes `is_absolute` true
    // and the rule is returned unchanged — but the intent was project-root-relative.
    let mut rules = vec!["Read(\\project\\src)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/root", "/home/user/root");
    assert_eq!(rules, vec!["Read(/home/user/root/project/src)"]);
}

#[skuld::test]
fn backslash_unc_share_as_absolute() {
    // B1 variant: `\\\\server\\share` (JSON-escaped UNC) normalizes to `//server/share`
    // which must be treated as the `//abs` marker and yield an absolute path.
    let mut rules = vec!["Write(\\\\server\\share\\**)".to_string()];
    resolve_rule_relative_paths(&mut rules, "/home/user/project", "/home/user/project");
    assert_eq!(rules, vec!["Write(/server/share/**)"]);
}
