use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
pub(crate) struct Settings {
    pub(crate) permissions: Option<PermissionsJson>,
}

#[derive(Deserialize)]
pub(crate) struct PermissionsJson {
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    #[serde(default)]
    pub(crate) deny: Vec<String>,
    #[serde(default)]
    pub(crate) ask: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct ManagedSettings {
    pub(crate) permissions: Option<PermissionsJson>,
    #[serde(default, rename = "allowManagedPermissionRulesOnly")]
    pub(crate) allow_managed_permission_rules_only: bool,
}

#[derive(Default, Clone)]
pub struct Permissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub ask: Vec<String>,
}

pub fn load_settings(cwd: &str) -> Permissions {
    // 1. Managed settings (highest authority)
    let (mut merged, managed_only) = load_managed();

    if managed_only {
        return merged;
    }

    // 2. Global settings
    if let Some(home) = dirs::home_dir() {
        let global = home.join(".claude/settings.json");
        merge_from(&global, &mut merged);
    }

    // 3. Project-level settings
    let project = Path::new(cwd).join(".claude/settings.json");
    merge_from(&project, &mut merged);

    // 4. Project-level local settings
    let local = Path::new(cwd).join(".claude/settings.local.json");
    merge_from(&local, &mut merged);

    merged
}

/// Testable merge logic that operates on string contents instead of file paths.
#[cfg(test)]
pub(crate) fn load_settings_from_contents(
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

fn merge_from(path: &Path, merged: &mut Permissions) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(settings) = serde_json::from_str::<Settings>(&content) else {
        return;
    };
    if let Some(perms) = settings.permissions {
        merge_permissions(merged, perms);
    }
}

fn merge_permissions(merged: &mut Permissions, perms: PermissionsJson) {
    merged.allow.extend(perms.allow);
    merged.deny.extend(perms.deny);
    merged.ask.extend(perms.ask);
}
