use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tempfile::NamedTempFile;
use thaum::ast::{Command as ShellCommand, Expression};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

use crate::cli::{classify_hook_command, HookCommandKind};
use crate::settings::{LoadedSettings, Permissions};

const CODEX_HOOK_MATCHERS: [&str; 2] = ["^Bash$", "^apply_patch$"];

#[derive(Debug, Clone, Copy)]
pub struct CodexConfigLayer<'a> {
    pub path: &'a str,
    pub content: &'a str,
}

#[derive(Default, Deserialize)]
struct CodexConfig {
    // `None` (key absent) vs `Some(vec![])` (explicit empty) are distinct, per
    // Codex: unset -> default markers; explicit empty -> detection disabled.
    #[serde(default)]
    project_root_markers: Option<Vec<String>>,
    #[serde(default)]
    projects: HashMap<String, CodexProjectConfig>,
    scriptcheck: Option<CodexScriptcheckConfig>,
}

#[derive(Default, Deserialize)]
struct CodexProjectConfig {
    trust_level: Option<String>,
}

#[derive(Default, Deserialize)]
struct CodexScriptcheckConfig {
    permissions: Option<CodexPermissions>,
}

#[derive(Default, Deserialize)]
struct CodexPermissions {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    ask: Vec<String>,
    #[serde(default, alias = "additionalDirectories")]
    additional_directories: Vec<String>,
}

pub fn load_codex_settings(cwd: &str) -> LoadedSettings {
    let system_content = codex_system_config_path().and_then(read_to_string_if_exists);
    let user_content = codex_user_config_path().and_then(read_to_string_if_exists);
    let markers = project_root_markers(system_content.as_deref(), user_content.as_deref());

    let project_root =
        find_codex_project_root(Path::new(cwd), &markers).unwrap_or_else(|| PathBuf::from(cwd));
    let project_root_str = crate::path_util::normalize_separators(&project_root.to_string_lossy());

    let project_layers = if project_is_trusted(user_content.as_deref(), &project_root_str) {
        codex_project_config_chain(&project_root, Path::new(cwd))
            .into_iter()
            .filter_map(|path| {
                let content = read_to_string_if_exists(path.clone())?;
                Some((path, content))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut loaded = load_codex_settings_from_contents(
        system_content.as_deref(),
        user_content.as_deref(),
        &[],
        cwd,
    );
    for (_, content) in project_layers {
        if let Some(config) = parse_config(Some(&content)) {
            merge_permissions(&mut loaded.permissions, config);
        }
    }
    loaded
}

pub fn install_codex_hooks(
    cwd: &str,
    binary_path: &str,
    project: bool,
) -> Result<PathBuf, CodexConfigFileError> {
    let config_path = codex_target_config_path(cwd, project, true)?;
    let install_command = format!("{binary_path} --agent codex");
    mutate_codex_config(&config_path, |content, hooks_json_exists| {
        install_codex_hooks_into_toml(content, &install_command, hooks_json_exists)
    })?;
    Ok(config_path)
}

pub fn uninstall_codex_hooks(
    cwd: &str,
    binary_path: &str,
    project: bool,
) -> Result<PathBuf, CodexConfigFileError> {
    let config_path = codex_target_config_path(cwd, project, false)?;
    mutate_codex_config(&config_path, |content, hooks_json_exists| {
        uninstall_codex_hooks_from_toml(content, binary_path, hooks_json_exists)
    })?;
    Ok(config_path)
}

pub fn detect_codex_project_root(cwd: &str) -> String {
    let system_content = codex_system_config_path().and_then(read_to_string_if_exists);
    let user_content = codex_user_config_path().and_then(read_to_string_if_exists);
    let markers = project_root_markers(system_content.as_deref(), user_content.as_deref());
    let root =
        find_codex_project_root(Path::new(cwd), &markers).unwrap_or_else(|| PathBuf::from(cwd));
    crate::path_util::normalize_separators(&root.to_string_lossy())
}

pub fn load_codex_settings_from_contents(
    system_content: Option<&str>,
    user_content: Option<&str>,
    project_layers: &[CodexConfigLayer<'_>],
    cwd: &str,
) -> LoadedSettings {
    let mut loaded = LoadedSettings::default();

    if let Some(config) = parse_config(system_content) {
        merge_permissions(&mut loaded.permissions, config);
    }
    if let Some(config) = parse_config(user_content) {
        merge_permissions(&mut loaded.permissions, config);
    }

    let markers = project_root_markers(system_content, user_content);
    let project_root = find_codex_project_root_from_paths(
        cwd,
        &project_layers
            .iter()
            .map(|layer| layer.path)
            .collect::<Vec<_>>(),
        &markers,
    )
    .unwrap_or_else(|| crate::path_util::normalize_separators(cwd));

    if !project_is_trusted(user_content, &project_root) {
        return loaded;
    }

    for layer in project_layers {
        if let Some(config) = parse_config(Some(layer.content)) {
            merge_permissions(&mut loaded.permissions, config);
        }
    }

    loaded
}

pub fn find_codex_project_root_from_paths(
    cwd: &str,
    existing_paths: &[&str],
    markers: &[String],
) -> Option<String> {
    let cwd = crate::path_util::normalize_separators(cwd);
    if markers.is_empty() {
        return Some(cwd);
    }

    let existing = existing_paths
        .iter()
        .map(|path| crate::path_util::normalize_separators(path))
        .collect::<Vec<_>>();

    let mut current = PathBuf::from(&cwd);
    loop {
        let current_str = crate::path_util::normalize_separators(&current.to_string_lossy());
        if markers.iter().any(|marker| {
            let marker_path =
                crate::path_util::normalize_separators(&current.join(marker).to_string_lossy());
            existing.iter().any(|path| path == &marker_path)
        }) {
            // First (nearest) marker going up wins, matching Codex's find_project_root.
            return Some(current_str);
        }

        if !current.pop() {
            break;
        }
    }

    // No marker found: fall back to the shortest ancestor that holds a
    // `.codex/config.toml` layer. NOTE: this differs from Codex, which uses cwd
    // when no marker matches; tracked for a follow-up that mirrors Codex's
    // project-root resolution exactly.
    let mut config_roots = existing
        .iter()
        .filter_map(|path| path.strip_suffix("/.codex/config.toml").map(str::to_string))
        .filter(|path| cwd == *path || cwd.starts_with(&format!("{path}/")))
        .collect::<Vec<_>>();
    config_roots.sort_by_key(|path| path.len());

    Some(config_roots.into_iter().next().unwrap_or(cwd))
}

pub fn codex_project_config_chain(project_root: &Path, cwd: &Path) -> Vec<PathBuf> {
    let mut current = cwd.to_path_buf();
    let mut chain = Vec::new();

    loop {
        chain.push(current.join(".codex/config.toml"));
        if current == project_root {
            break;
        }
        if !current.starts_with(project_root) || !current.pop() {
            break;
        }
    }

    chain.reverse();
    chain
}

fn find_codex_project_root(cwd: &Path, markers: &[String]) -> Option<PathBuf> {
    if markers.is_empty() {
        return Some(cwd.to_path_buf());
    }

    let mut current = cwd.to_path_buf();
    loop {
        if markers.iter().any(|marker| current.join(marker).exists()) {
            // First (nearest) marker going up wins, matching Codex's find_project_root.
            return Some(current);
        }

        if !current.pop() {
            break;
        }
    }

    Some(cwd.to_path_buf())
}

fn project_root_markers(system_content: Option<&str>, user_content: Option<&str>) -> Vec<String> {
    // Fold layers low->high (system, then user). A layer that SETS the key
    // (Some, including an explicit empty list) REPLACES the accumulator; a layer
    // that does not set it leaves the accumulator unchanged. After folding,
    // `None` (no layer set it) falls back to the default `[".git"]`, while
    // `Some(list)` is used as-is — an explicit empty list stays empty (which
    // disables upward detection). Mirrors Codex project_root_markers resolution.
    let mut markers: Option<Vec<String>> = None;
    for content in [system_content, user_content] {
        if let Some(config) = parse_document(content) {
            if let Some(list) = config.project_root_markers {
                markers = Some(list);
            }
        }
    }
    markers.unwrap_or_else(|| vec![".git".to_string()])
}

fn project_is_trusted(user_content: Option<&str>, project_root: &str) -> bool {
    let Some(config) = parse_document(user_content) else {
        return false;
    };

    let project_root = crate::path_util::normalize_separators(project_root);
    let canonical_project_root = crate::canonicalize::best_effort_canonicalize(&project_root);

    config.projects.iter().any(|(path, project)| {
        let normalized_path = crate::path_util::normalize_separators(path);
        let canonical_path = crate::canonicalize::best_effort_canonicalize(&normalized_path);
        (crate::path_util::paths_equal_for_platform(&normalized_path, &project_root)
            || crate::path_util::paths_equal_for_platform(&normalized_path, &canonical_project_root)
            || crate::path_util::paths_equal_for_platform(&canonical_path, &project_root)
            || crate::path_util::paths_equal_for_platform(&canonical_path, &canonical_project_root))
            && project.trust_level.as_deref() == Some("trusted")
    })
}

fn parse_config(content: Option<&str>) -> Option<CodexPermissions> {
    parse_document(content)?
        .scriptcheck
        .and_then(|section| section.permissions)
}

fn parse_document(content: Option<&str>) -> Option<CodexConfig> {
    toml::from_str(content?).ok()
}

fn merge_permissions(merged: &mut Permissions, perms: CodexPermissions) {
    merged.allow.extend(perms.allow);
    merged.deny.extend(perms.deny);
    merged.ask.extend(perms.ask);
    merged
        .additional_directories
        .extend(perms.additional_directories);
}

fn codex_user_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|path| path.join(".codex")))?;
    Some(home.join("config.toml"))
}

fn codex_target_config_path(
    cwd: &str,
    project: bool,
    require_trusted_project: bool,
) -> Result<PathBuf, CodexConfigFileError> {
    if project {
        let project_root = detect_codex_project_root(cwd);
        if require_trusted_project && !codex_project_is_trusted(&project_root) {
            return Err(CodexConfigFileError::UntrustedProject(project_root));
        }
        return Ok(PathBuf::from(project_root).join(".codex/config.toml"));
    }

    codex_user_config_path().ok_or(CodexConfigFileError::MissingCodexHome)
}

fn codex_system_config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        // Codex loads the machine-wide layer from
        // `<ProgramData>\OpenAI\Codex\config.toml`, resolving ProgramData via
        // SHGetKnownFolderPath(FOLDERID_ProgramData). We approximate with the
        // `%ProgramData%` env var (default `C:\ProgramData`) to avoid a heavy
        // windows-sys/FFI dependency; this matches Codex's literal fallback.
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Some(program_data.join("OpenAI").join("Codex").join("config.toml"))
    }
    #[cfg(not(windows))]
    {
        // macOS and Linux both use /etc/codex/config.toml.
        Some(PathBuf::from("/etc/codex/config.toml"))
    }
}

fn read_to_string_if_exists(path: PathBuf) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn codex_project_is_trusted(project_root: &str) -> bool {
    let user_content = codex_user_config_path().and_then(read_to_string_if_exists);
    project_is_trusted(user_content.as_deref(), project_root)
}

fn mutate_codex_config<F>(config_path: &Path, mutate: F) -> Result<(), CodexConfigFileError>
where
    F: FnOnce(&str, bool) -> Result<String, CodexTomlMutationError>,
{
    let hooks_json_exists = config_path
        .parent()
        .is_some_and(|parent| parent.join("hooks.json").exists());
    let original = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(CodexConfigFileError::Read {
                path: config_path.to_path_buf(),
                source: error,
            });
        }
    };
    let updated = mutate(&original, hooks_json_exists).map_err(CodexConfigFileError::Mutation)?;
    if updated == original {
        return Ok(());
    }
    if updated.is_empty() && !config_path.exists() {
        return Ok(());
    }

    write_codex_config_atomic(config_path, &updated)
}

fn write_codex_config_atomic(
    config_path: &Path,
    content: &str,
) -> Result<(), CodexConfigFileError> {
    let Some(parent) = config_path.parent() else {
        return Err(CodexConfigFileError::MissingConfigParent(
            config_path.to_path_buf(),
        ));
    };
    std::fs::create_dir_all(parent).map_err(|source| CodexConfigFileError::CreateDir {
        path: parent.to_path_buf(),
        source,
    })?;

    let mut temp_file =
        NamedTempFile::new_in(parent).map_err(|source| CodexConfigFileError::CreateTemp {
            path: parent.to_path_buf(),
            source,
        })?;
    temp_file
        .write_all(content.as_bytes())
        .and_then(|_| temp_file.flush())
        .map_err(|source| CodexConfigFileError::Write {
            path: config_path.to_path_buf(),
            source,
        })?;
    temp_file
        .persist(config_path)
        .map(|_| ())
        .map_err(|error| CodexConfigFileError::Write {
            path: config_path.to_path_buf(),
            source: error.error,
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexTomlMutationError {
    HooksJsonExists,
    InvalidInstallCommand,
    InvalidBinaryPath,
    InvalidToml(String),
    UnexpectedTomlType(String),
}

impl std::fmt::Display for CodexTomlMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HooksJsonExists => {
                write!(
                    f,
                    "Refusing to modify config.toml while sibling hooks.json exists"
                )
            }
            Self::InvalidInstallCommand => {
                write!(f, "Install command must be a direct simple command")
            }
            Self::InvalidBinaryPath => {
                write!(f, "Binary path must not be empty")
            }
            Self::InvalidToml(error) => write!(f, "Failed to parse config.toml: {error}"),
            Self::UnexpectedTomlType(path) => {
                write!(f, "Expected TOML table/array shape at {path}")
            }
        }
    }
}

impl std::error::Error for CodexTomlMutationError {}

#[derive(Debug)]
pub enum CodexConfigFileError {
    MissingCodexHome,
    MissingConfigParent(PathBuf),
    UntrustedProject(String),
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    CreateTemp {
        path: PathBuf,
        source: std::io::Error,
    },
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    Mutation(CodexTomlMutationError),
}

impl std::fmt::Display for CodexConfigFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCodexHome => {
                write!(
                    f,
                    "Could not determine the Codex config path from CODEX_HOME or HOME"
                )
            }
            Self::MissingConfigParent(path) => {
                write!(f, "Config path has no parent directory: {}", path.display())
            }
            Self::UntrustedProject(project_root) => {
                write!(
                    f,
                    "Refusing to install project Codex hooks for an untrusted project: {project_root}"
                )
            }
            Self::CreateDir { path, source } => {
                write!(f, "Failed to create {}: {source}", path.display())
            }
            Self::CreateTemp { path, source } => {
                write!(
                    f,
                    "Failed to create a temporary config file in {}: {source}",
                    path.display()
                )
            }
            Self::Read { path, source } => {
                write!(f, "Failed to read {}: {source}", path.display())
            }
            Self::Write { path, source } => {
                write!(f, "Failed to write {}: {source}", path.display())
            }
            Self::Mutation(source) => source.fmt(f),
        }
    }
}

impl std::error::Error for CodexConfigFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDir { source, .. }
            | Self::CreateTemp { source, .. }
            | Self::Read { source, .. }
            | Self::Write { source, .. } => Some(source),
            Self::Mutation(source) => Some(source),
            Self::MissingCodexHome | Self::MissingConfigParent(_) | Self::UntrustedProject(_) => {
                None
            }
        }
    }
}

pub fn install_codex_hooks_into_toml(
    input: &str,
    install_command: &str,
    hooks_json_exists: bool,
) -> Result<String, CodexTomlMutationError> {
    if hooks_json_exists {
        return Err(CodexTomlMutationError::HooksJsonExists);
    }

    let install_arg0 = parse_direct_command_arg0(install_command)
        .ok_or(CodexTomlMutationError::InvalidInstallCommand)?;
    if !command_is_owned_codex_handler(install_command, &install_arg0) {
        return Err(CodexTomlMutationError::InvalidInstallCommand);
    }
    let mut doc = parse_toml_document(input)?;

    ensure_features_hooks_enabled(&mut doc)?;
    let pre_tool_use = ensure_pre_tool_use_array(&mut doc)?;
    for matcher in CODEX_HOOK_MATCHERS {
        upsert_codex_hook(pre_tool_use, matcher, install_command, &install_arg0);
    }

    Ok(doc.to_string())
}

pub fn uninstall_codex_hooks_from_toml(
    input: &str,
    binary_path: &str,
    hooks_json_exists: bool,
) -> Result<String, CodexTomlMutationError> {
    if hooks_json_exists {
        return Err(CodexTomlMutationError::HooksJsonExists);
    }
    if binary_path.trim().is_empty() {
        return Err(CodexTomlMutationError::InvalidBinaryPath);
    }

    let mut doc = parse_toml_document(input)?;
    let Some(hooks_table) = doc.get_mut("hooks").and_then(Item::as_table_mut) else {
        return Ok(doc.to_string());
    };
    let Some(pre_tool_use) = hooks_table
        .get_mut("PreToolUse")
        .and_then(Item::as_array_of_tables_mut)
    else {
        return Ok(doc.to_string());
    };

    let mut retained_entries = ArrayOfTables::new();
    for entry in pre_tool_use.iter() {
        let mut entry = entry.clone();
        let Some(entry_hooks) = entry
            .get_mut("hooks")
            .and_then(Item::as_array_of_tables_mut)
        else {
            retained_entries.push(entry);
            continue;
        };

        let mut retained_hooks = ArrayOfTables::new();
        for hook in entry_hooks.iter() {
            if !is_owned_codex_hook(hook, binary_path) {
                retained_hooks.push(hook.clone());
            }
        }

        if retained_hooks.is_empty() {
            continue;
        }

        entry["hooks"] = Item::ArrayOfTables(retained_hooks);
        retained_entries.push(entry);
    }

    if retained_entries.is_empty() {
        hooks_table.remove("PreToolUse");
    } else {
        hooks_table["PreToolUse"] = Item::ArrayOfTables(retained_entries);
    }

    Ok(doc.to_string())
}

fn parse_toml_document(input: &str) -> Result<DocumentMut, CodexTomlMutationError> {
    if input.trim().is_empty() {
        return Ok(DocumentMut::new());
    }

    input
        .parse::<DocumentMut>()
        .map_err(|error| CodexTomlMutationError::InvalidToml(error.to_string()))
}

fn ensure_features_hooks_enabled(doc: &mut DocumentMut) -> Result<(), CodexTomlMutationError> {
    if doc.as_table().contains_key("features") && !doc["features"].is_table() {
        return Err(CodexTomlMutationError::UnexpectedTomlType(
            "features".to_string(),
        ));
    }
    if !doc.as_table().contains_key("features") {
        doc["features"] = Item::Table(Table::new());
    }
    doc["features"]["hooks"] = value(true);
    Ok(())
}

fn ensure_pre_tool_use_array(
    doc: &mut DocumentMut,
) -> Result<&mut ArrayOfTables, CodexTomlMutationError> {
    if doc.as_table().contains_key("hooks") && !doc["hooks"].is_table() {
        return Err(CodexTomlMutationError::UnexpectedTomlType(
            "hooks".to_string(),
        ));
    }
    if !doc.as_table().contains_key("hooks") {
        doc["hooks"] = Item::Table(Table::new());
    }
    let hooks = doc["hooks"]
        .as_table_mut()
        .expect("hooks should be a table");
    if hooks.contains_key("PreToolUse") && !hooks["PreToolUse"].is_array_of_tables() {
        return Err(CodexTomlMutationError::UnexpectedTomlType(
            "hooks.PreToolUse".to_string(),
        ));
    }
    if !hooks.contains_key("PreToolUse") {
        doc["hooks"]["PreToolUse"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    Ok(doc["hooks"]["PreToolUse"]
        .as_array_of_tables_mut()
        .expect("PreToolUse should be an array of tables"))
}

fn upsert_codex_hook(
    pre_tool_use: &mut ArrayOfTables,
    matcher: &str,
    install_command: &str,
    install_arg0: &str,
) {
    for entry in pre_tool_use.iter_mut() {
        if entry.get("matcher").and_then(Item::as_str) != Some(matcher) {
            continue;
        }

        replace_or_append_owned_hook(entry, install_command, install_arg0);
        return;
    }

    let mut entry = Table::new();
    entry["matcher"] = value(matcher);
    entry["hooks"] = Item::ArrayOfTables(ArrayOfTables::new());
    replace_or_append_owned_hook(&mut entry, install_command, install_arg0);
    pre_tool_use.push(entry);
}

fn replace_or_append_owned_hook(entry: &mut Table, install_command: &str, install_arg0: &str) {
    if !entry["hooks"].is_array_of_tables() {
        entry["hooks"] = Item::ArrayOfTables(ArrayOfTables::new());
    }

    let existing_hooks = entry["hooks"]
        .as_array_of_tables()
        .expect("hooks should be an array of tables")
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut rewritten_hooks = ArrayOfTables::new();
    let mut inserted = false;

    for hook in existing_hooks {
        if is_owned_codex_hook(&hook, install_arg0) {
            if !inserted {
                rewritten_hooks.push(new_command_hook(install_command));
                inserted = true;
            }
            continue;
        }
        rewritten_hooks.push(hook);
    }

    if !inserted {
        rewritten_hooks.push(new_command_hook(install_command));
    }

    entry["hooks"] = Item::ArrayOfTables(rewritten_hooks);
}

fn new_command_hook(command: &str) -> Table {
    let mut hook = Table::new();
    hook["type"] = value("command");
    hook["command"] = value(command);
    hook
}

fn is_owned_codex_hook(hook: &Table, binary_path: &str) -> bool {
    if hook.get("type").and_then(Item::as_str) != Some("command") {
        return false;
    }

    hook.get("command")
        .and_then(Item::as_str)
        .is_some_and(|command| command_is_owned_codex_handler(command, binary_path))
}

fn command_is_owned_codex_handler(command: &str, binary_path: &str) -> bool {
    if classify_hook_command(command, binary_path)
        .is_some_and(|kind| matches!(kind, HookCommandKind::Codex))
    {
        return true;
    }

    let program = match thaum::parse_with(command, thaum::Dialect::Bash) {
        Ok(program) => program,
        Err(_) => return false,
    };
    if program.statements.len() != 1 {
        return false;
    }

    let Expression::Command(ShellCommand {
        assignments,
        arguments,
        redirects,
        ..
    }) = &program.statements[0].expression
    else {
        return false;
    };

    if !assignments.is_empty() || !redirects.is_empty() {
        return false;
    }

    let arguments = match arguments
        .iter()
        .map(|arg| arg.try_to_static_string())
        .collect::<Option<Vec<_>>>()
    {
        Some(arguments) => arguments,
        None => return false,
    };
    let Some(arg0) = arguments.first() else {
        return false;
    };
    if arg0.contains('/') || arg0.contains('\\') || strip_pathext(arg0) != "claude-scriptcheck" {
        return false;
    }

    matches!(
        parse_agent(arguments.iter().skip(1).map(String::as_str)),
        Some("codex")
    )
}

fn parse_direct_command_arg0(command: &str) -> Option<String> {
    let program = thaum::parse_with(command, thaum::Dialect::Bash).ok()?;
    if program.statements.len() != 1 {
        return None;
    }

    let Expression::Command(ShellCommand {
        assignments,
        arguments,
        redirects,
        ..
    }) = &program.statements[0].expression
    else {
        return None;
    };

    if !assignments.is_empty() || !redirects.is_empty() {
        return None;
    }

    arguments.first()?.try_to_static_string()
}

fn strip_pathext(path: &str) -> String {
    crate::path_util::strip_pathext_suffix(path).to_string()
}

fn parse_agent<'a>(mut arguments: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut agent = None;

    while let Some(argument) = arguments.next() {
        if argument == "--agent" {
            let value = arguments.next()?;
            if value.starts_with('-') || agent.is_some() {
                return None;
            }
            agent = Some(value);
            continue;
        }

        if let Some(value) = argument.strip_prefix("--agent=") {
            if value.is_empty() || agent.is_some() {
                return None;
            }
            agent = Some(value);
            continue;
        }

        return None;
    }

    agent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_config_path_is_platform_appropriate() {
        let s = codex_system_config_path()
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        #[cfg(windows)]
        assert!(
            s.ends_with("OpenAI/Codex/config.toml"),
            "windows system path should live under ProgramData/OpenAI/Codex, got {s}"
        );
        #[cfg(not(windows))]
        assert_eq!(s, "/etc/codex/config.toml");
    }

    #[test]
    fn markers_unset_defaults_to_git() {
        assert_eq!(project_root_markers(None, None), vec![".git".to_string()]);
    }

    #[test]
    fn markers_explicit_empty_disables_detection() {
        // An explicit empty list is distinct from unset: detection disabled.
        assert_eq!(
            project_root_markers(None, Some("project_root_markers = []\n")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn markers_custom_list_is_used() {
        assert_eq!(
            project_root_markers(None, Some("project_root_markers = [\".hg\", \".jj\"]\n")),
            vec![".hg".to_string(), ".jj".to_string()]
        );
    }

    #[test]
    fn markers_user_empty_overrides_system_nonempty() {
        // A higher-precedence layer that sets the key (even empty) replaces.
        assert_eq!(
            project_root_markers(
                Some("project_root_markers = [\".git\"]\n"),
                Some("project_root_markers = []\n"),
            ),
            Vec::<String>::new()
        );
    }
}
