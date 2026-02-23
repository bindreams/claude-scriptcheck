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
