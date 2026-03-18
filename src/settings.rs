use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
pub struct Settings {
    pub permissions: Option<PermissionsJson>,
}

#[derive(Deserialize)]
pub struct PermissionsJson {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
}

#[derive(Deserialize)]
pub struct ManagedSettings {
    pub permissions: Option<PermissionsJson>,
    #[serde(default, rename = "allowManagedPermissionRulesOnly")]
    pub allow_managed_permission_rules_only: bool,
}

#[derive(Default, Clone)]
pub struct Permissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub ask: Vec<String>,
}

/// Load and merge permission rules from all settings files.
///
/// `cwd` is the current working directory (used for bare/`./` relative paths).
/// `project_root` is the project root directory, typically `$CLAUDE_PROJECT_DIR`
/// (used for `/path` project-root-relative patterns and locating settings files).
pub fn load_settings(cwd: &str, project_root: &str) -> Permissions {
    // 1. Managed settings (highest authority)
    let (mut merged, managed_only) = load_managed();

    if managed_only {
        return merged;
    }

    // 2. Global settings
    if let Some(home) = dirs::home_dir() {
        let global = home.join(".claude/settings.json");
        merge_from_with_base(&global, cwd, project_root, &mut merged);
    }

    // 3. Project-level settings (located at project root)
    let project = Path::new(project_root).join(".claude/settings.json");
    merge_from_with_base(&project, cwd, project_root, &mut merged);

    // 4. Project-level local settings (located at project root)
    let local = Path::new(project_root).join(".claude/settings.local.json");
    merge_from_with_base(&local, cwd, project_root, &mut merged);

    merged
}

/// Testable merge logic that operates on string contents instead of file paths.
pub fn load_settings_from_contents(
    managed_content: Option<&str>,
    settings_contents: &[&str],
) -> Permissions {
    let mut merged = Permissions::default();
    let mut managed_only = false;

    if let Some(content) = managed_content {
        if let Ok(ms) = serde_json::from_str::<ManagedSettings>(content) {
            managed_only = ms.allow_managed_permission_rules_only;
            if let Some(perms) = ms.permissions {
                merge_permissions(&mut merged, perms);
            }
        }
    }

    if managed_only {
        return merged;
    }

    for content in settings_contents {
        if let Ok(settings) = serde_json::from_str::<Settings>(content) {
            if let Some(perms) = settings.permissions {
                merge_permissions(&mut merged, perms);
            }
        }
    }

    merged
}

fn load_managed() -> (Permissions, bool) {
    let mut merged = Permissions::default();

    let path = managed_settings_path();
    let Ok(content) = std::fs::read_to_string(path) else {
        return (merged, false);
    };
    let Ok(ms) = serde_json::from_str::<ManagedSettings>(&content) else {
        return (merged, false);
    };

    let managed_only = ms.allow_managed_permission_rules_only;
    if let Some(perms) = ms.permissions {
        merge_permissions(&mut merged, perms);
    }

    (merged, managed_only)
}

fn managed_settings_path() -> &'static str {
    if cfg!(target_os = "macos") {
        "/Library/Application Support/ClaudeCode/managed-settings.json"
    } else {
        "/etc/claude-code/managed-settings.json"
    }
}

fn merge_from_with_base(path: &Path, cwd: &str, project_root: &str, merged: &mut Permissions) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(settings) = serde_json::from_str::<Settings>(&content) else {
        return;
    };
    if let Some(mut perms) = settings.permissions {
        resolve_rule_relative_paths(&mut perms.allow, cwd, project_root);
        resolve_rule_relative_paths(&mut perms.deny, cwd, project_root);
        resolve_rule_relative_paths(&mut perms.ask, cwd, project_root);
        merge_permissions(merged, perms);
    }
}

fn merge_permissions(merged: &mut Permissions, perms: PermissionsJson) {
    merged.allow.extend(perms.allow);
    merged.deny.extend(perms.deny);
    merged.ask.extend(perms.ask);
}

/// Resolve paths in file rules (Read/Write/Edit) following Claude Code's 4-tier scheme:
///
/// - `//path` → absolute filesystem path (strip one `/`)
/// - `~/path` → home-relative (left as-is, expanded later in `parse_single_rule`)
/// - `/path`  → project-root-relative (prepend `project_root`)
/// - `path` or `./path` → CWD-relative (prepend `cwd`)
///
/// Only Read(...), Write(...), and Edit(...) rules are affected.
pub fn resolve_rule_relative_paths(rules: &mut [String], cwd: &str, project_root: &str) {
    for rule in rules.iter_mut() {
        *rule = resolve_one_rule(rule, cwd, project_root);
    }
}

fn resolve_one_rule(rule: &str, cwd: &str, project_root: &str) -> String {
    for prefix in ["Read(", "Write(", "Edit("] {
        if let Some(inner) = rule.strip_prefix(prefix).and_then(|s| s.strip_suffix(')')) {
            let kind = &prefix[..prefix.len() - 1]; // "Read", "Write", or "Edit"
            if let Some(abs) = inner.strip_prefix("//") {
                // //path → absolute filesystem path
                // On Windows, //C:/foo strips to C:/foo which is already absolute
                if crate::path_util::is_absolute(abs) {
                    return format!("{kind}({abs})");
                }
                return format!("{kind}(/{abs})");
            }
            if inner.starts_with('~') {
                // ~/path → home-relative, expanded later in parse_single_rule
                return rule.to_string();
            }
            if inner.starts_with('/') {
                // /path → project-root-relative (inner already has leading /)
                return format!("{kind}({project_root}{inner})");
            }
            // Check for Windows drive-letter or UNC paths (C:/..., \\server\...)
            // These are already absolute and should not be treated as relative.
            if crate::path_util::is_absolute(inner) {
                return rule.to_string();
            }
            // bare path or ./path → CWD-relative
            return format!("{kind}({cwd}/{inner})");
        }
    }
    rule.to_string()
}
