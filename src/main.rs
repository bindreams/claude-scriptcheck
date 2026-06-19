use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process;

use claude_scriptcheck::apply_patch;
use claude_scriptcheck::args::{Agent, Cli, Commands};
use claude_scriptcheck::checker::{CheckResult, Decision};
use claude_scriptcheck::codex_settings;
use claude_scriptcheck::file_access::{self, AccessKind, FileAccess};
use claude_scriptcheck::permission_mode::PermissionMode;
use claude_scriptcheck::{checker, cli, hook, logging, path_util, permission};
use thaum::ast::{Command as ShellCommand, Expression};
use thaum::span::Span;

fn main() {
    let cli = Cli::parse_and_validate();

    match cli.command {
        Some(Commands::Install { agent, project }) => install(agent, project),
        Some(Commands::Uninstall { agent, project }) => uninstall(agent, project),
        Some(Commands::Check {
            agent,
            command,
            cwd,
            permission_mode,
        }) => check(agent, &command, &cwd, permission_mode),
        Some(Commands::Log {
            clear,
            follow,
            tail,
            allow,
            no_allow,
            ask,
            no_ask,
            deny,
            no_deny,
        }) => {
            // Default is shown (when neither --flag nor --no-flag is passed).
            // `overrides_with` ensures last-one-wins when both are passed.
            let filter = cli::VerdictFilter {
                show_allow: allow || !no_allow,
                show_ask: ask || !no_ask,
                show_deny: deny || !no_deny,
            };
            cli::log(clear, follow, tail, &filter);
        }
        Some(Commands::LogPath) => cli::log_path(),
        Some(Commands::Upgrade) => cli::upgrade(),
        None => run_hook(cli.agent.expect("validated hook agent")),
    }
}

fn install(agent: Agent, project: bool) {
    match agent {
        Agent::Claude => {
            cli::install(project);
            rewrite_installed_hook_commands(project, agent);
        }
        Agent::Codex => {
            let cwd = current_cwd();
            let binary_path = cli::current_binary_path();
            let config_path = codex_settings::install_codex_hooks(&cwd, &binary_path, project)
                .unwrap_or_else(|error| {
                    eprintln!("{error}");
                    process::exit(1);
                });
            eprintln!("Installed Codex hook in {}", config_path.display());
            eprintln!("Binary: {binary_path}");
        }
    }
}

fn uninstall(agent: Agent, project: bool) {
    match agent {
        Agent::Claude => cli::uninstall(project),
        Agent::Codex => {
            let cwd = current_cwd();
            let binary_path = cli::current_binary_path();
            let config_path = codex_settings::uninstall_codex_hooks(&cwd, &binary_path, project)
                .unwrap_or_else(|error| {
                    eprintln!("{error}");
                    process::exit(1);
                });
            eprintln!("Uninstalled Codex hook from {}", config_path.display());
        }
    }
}

fn check(agent: Agent, command: &str, cwd: &str, permission_mode: Option<PermissionMode>) {
    match agent {
        Agent::Claude => cli::check(command, cwd, permission_mode),
        Agent::Codex => {
            let resolved_cwd = if cwd == "." {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("/"))
                    .to_string_lossy()
                    .to_string()
            } else {
                cwd.to_string()
            };
            let resolved_cwd = path_util::normalize_separators(&resolved_cwd);
            let project_root = project_root_for_agent(agent, &resolved_cwd);
            let parsed_perms =
                load_permissions_for_agent(agent, &resolved_cwd, &project_root, permission_mode);

            let result = match thaum::parse_with(command, thaum::Dialect::Bash) {
                Ok(program) => checker::check_program(&program, &parsed_perms, &resolved_cwd),
                Err(_) => checker::CheckResult {
                    decision: checker::Decision::Ask,
                    matched_allow: vec![],
                    matched_deny: vec![],
                    missing_rules: vec!["Bash(<parse error>)".into()],
                    custom_reason: Some("Shell command could not be parsed".into()),
                },
            };
            let result = checker::apply_permission_mode(result, permission_mode);

            match result.decision {
                checker::Decision::Allow => {
                    let reason = result
                        .custom_reason
                        .as_deref()
                        .unwrap_or("All commands and file accesses are permitted");
                    println!("ALLOW: {reason}");
                }
                checker::Decision::Deny(reason) => {
                    println!("DENY: {reason}");
                    process::exit(1);
                }
                checker::Decision::Ask => {
                    let header = result
                        .custom_reason
                        .as_deref()
                        .unwrap_or("Missing permission rules");
                    println!("ASK: {header}:");
                    for rule in &result.missing_rules {
                        println!("  - {rule}");
                    }
                }
            }
        }
    }
}

fn rewrite_installed_hook_commands(project: bool, agent: Agent) {
    let settings_path = claude_settings_path(project);
    let Ok(content) = std::fs::read_to_string(&settings_path) else {
        return;
    };
    let Ok(mut root) = serde_json::from_str::<serde_json::Value>(&content) else {
        return;
    };

    let Some(pre_tool_use) = root
        .get_mut("hooks")
        .and_then(|hooks| hooks.get_mut("PreToolUse"))
        .and_then(|entries| entries.as_array_mut())
    else {
        return;
    };

    let mut changed = false;
    for entry in pre_tool_use {
        let Some(matcher) = entry.get("matcher").and_then(|matcher| matcher.as_str()) else {
            continue;
        };
        if !cli::SUPPORTED_MATCHERS.contains(&matcher) {
            continue;
        }
        let Some(hooks) = entry
            .get_mut("hooks")
            .and_then(|hooks| hooks.as_array_mut())
        else {
            continue;
        };
        for hook in hooks {
            if hook.get("type").and_then(|kind| kind.as_str()) != Some("command") {
                continue;
            }
            let Some(command) = hook.get("command").and_then(|command| command.as_str()) else {
                continue;
            };
            if let Some(rewritten) = rewrite_hook_command(command, agent) {
                hook["command"] = serde_json::json!(rewritten);
                changed = true;
            }
        }
    }

    if changed {
        write_settings_json(&settings_path, &root);
    }
}

fn rewrite_hook_command(command: &str, agent: Agent) -> Option<String> {
    // Parse against a `\`-to-`/` copy so Windows path separators aren't mangled
    // by the bash parser. That replacement is 1 byte for 1 byte, so the parsed
    // spans stay byte-aligned with `command`; slice the original to preserve the
    // user's path separators in the rewritten hook.
    let normalized = command.replace('\\', "/");
    let cmd = parse_rewritable_hook_command(&normalized)?;
    if cmd.agent != HookCommandAgent::Missing {
        return None;
    }

    let mut rewritten: Vec<&str> = cmd
        .arguments
        .iter()
        .map(|span| &command[span.start.0..span.end.0])
        .collect();
    rewritten.push("--agent");
    rewritten.push(agent.as_str());
    Some(rewritten.join(" "))
}

struct RewritableHookCommand {
    arguments: Vec<Span>,
    agent: HookCommandAgent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HookCommandAgent {
    Missing,
    Named(String),
    Invalid,
}

fn parse_rewritable_hook_command(command: &str) -> Option<RewritableHookCommand> {
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

    let arguments: Vec<(Span, String)> = arguments
        .iter()
        .map(|arg| Some((arg.span(), arg.try_to_static_string()?)))
        .collect::<Option<_>>()?;
    let (_, arg0) = arguments.first()?;
    if !cli::scriptcheck_arg0_is_owned(arg0) {
        return None;
    }

    Some(RewritableHookCommand {
        arguments: arguments.iter().map(|(span, _)| *span).collect(),
        agent: parse_hook_command_agent(&arguments),
    })
}

fn parse_hook_command_agent(arguments: &[(Span, String)]) -> HookCommandAgent {
    let mut values = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        let (_, value) = &arguments[index];
        if value == "--agent" {
            let Some((_, next_value)) = arguments.get(index + 1) else {
                return HookCommandAgent::Invalid;
            };
            if next_value.starts_with('-') {
                return HookCommandAgent::Invalid;
            }
            values.push(next_value.clone());
            index += 2;
            continue;
        }

        if let Some(value) = value.strip_prefix("--agent=") {
            if value.is_empty() {
                return HookCommandAgent::Invalid;
            }
            values.push(value.to_string());
            index += 1;
            continue;
        }

        return HookCommandAgent::Invalid;
    }

    match values.as_slice() {
        [] => HookCommandAgent::Missing,
        [value] => HookCommandAgent::Named(value.clone()),
        _ => HookCommandAgent::Invalid,
    }
}

fn claude_settings_path(project: bool) -> PathBuf {
    if project {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        cwd.join(".claude/settings.json")
    } else {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".claude/settings.json")
    }
}

fn current_cwd() -> String {
    path_util::normalize_separators(
        &std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .to_string_lossy(),
    )
}

fn write_settings_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directory {}: {e}", parent.display());
            process::exit(1);
        });
    }
    let content = serde_json::to_string_pretty(value).unwrap();
    std::fs::write(path, content).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {e}", path.display());
        process::exit(1);
    });
}

/// Hook mode: reads JSON from stdin and emits the agent-specific hook response.
fn run_hook(agent: Agent) {
    let mut input_str = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input_str) {
        eprintln!("Failed to read stdin: {e}");
        process::exit(2);
    }
    run_hook_with_input(agent, read_hook_input(&input_str));
}

fn read_hook_input(input_str: &str) -> hook::HookInput {
    match serde_json::from_str(input_str) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to parse hook input: {e}");
            process::exit(2);
        }
    }
}

fn run_hook_with_input(agent: Agent, hook_input: hook::HookInput) {
    // Normalize path separators (Windows backslashes → forward slashes).
    let cwd = path_util::normalize_separators(&hook_input.cwd);
    let project_root = project_root_for_agent(agent, &cwd);
    let permission_mode = PermissionMode::from_hook_str(hook_input.permission_mode.as_deref());
    let parsed_perms = load_permissions_for_agent(agent, &cwd, &project_root, permission_mode);

    match agent {
        Agent::Claude => match hook_input.tool_name.as_str() {
            "Bash" | "Monitor" => handle_bash(
                agent,
                &hook_input,
                &parsed_perms,
                &cwd,
                &project_root,
                permission_mode,
            ),
            "Grep" | "Glob" => handle_file_search(
                agent,
                &hook_input,
                &parsed_perms,
                &cwd,
                &project_root,
                permission_mode,
            ),
            "Read" => handle_file_tool(
                agent,
                &hook_input,
                &parsed_perms,
                &cwd,
                &project_root,
                permission_mode,
                AccessKind::Read,
            ),
            "Write" | "Edit" => handle_file_tool(
                agent,
                &hook_input,
                &parsed_perms,
                &cwd,
                &project_root,
                permission_mode,
                AccessKind::Write,
            ),
            _ => process::exit(0),
        },
        Agent::Codex => match hook_input.tool_name.as_str() {
            "Bash" => handle_bash(
                agent,
                &hook_input,
                &parsed_perms,
                &cwd,
                &project_root,
                permission_mode,
            ),
            "apply_patch" => handle_apply_patch(
                agent,
                &hook_input,
                &parsed_perms,
                &cwd,
                &project_root,
                permission_mode,
            ),
            _ => process::exit(0),
        },
    }
}

fn project_root_for_agent(agent: Agent, cwd: &str) -> String {
    match agent {
        Agent::Claude => std::env::var("CLAUDE_PROJECT_DIR")
            .map(|s| path_util::normalize_separators(&s))
            .unwrap_or_else(|_| cwd.to_string()),
        Agent::Codex => codex_settings::detect_codex_project_root(cwd),
    }
}

fn load_permissions_for_agent(
    agent: Agent,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) -> permission::ParsedPermissions {
    match agent {
        Agent::Claude => permission::load_perms(cwd, project_root, permission_mode),
        Agent::Codex => permission::load_perms_from_settings(
            codex_settings::load_codex_settings(cwd),
            cwd,
            project_root,
            permission_mode,
        ),
    }
}

/// Handle the Bash tool: parse the command with thaum and walk the AST.
fn handle_bash(
    agent: Agent,
    hook_input: &hook::HookInput,
    parsed_perms: &permission::ParsedPermissions,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) {
    let command = match &hook_input.tool_input.command {
        Some(cmd) if !cmd.is_empty() => cmd.clone(),
        _ => process::exit(0),
    };

    // Parse the bash command with thaum. On parse failure, construct a synthetic
    // Ask result with custom_reason so the original error message is preserved
    // through the apply_permission_mode transform.
    let result = match thaum::parse_with(&command, thaum::Dialect::Bash) {
        Ok(program) => checker::check_program(&program, parsed_perms, cwd),
        Err(_) => CheckResult {
            decision: Decision::Ask,
            matched_allow: vec![],
            matched_deny: vec![],
            missing_rules: vec![format!("{}(<parse error>)", hook_input.tool_name)],
            custom_reason: Some("Shell command could not be parsed".into()),
        },
    };

    let result = checker::apply_permission_mode(result, permission_mode);
    log_and_output(
        agent,
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        &command,
        &command,
    );
}

/// Handle Grep and Glob tools: check the search path against Read rules.
fn handle_file_search(
    agent: Agent,
    hook_input: &hook::HookInput,
    parsed_perms: &permission::ParsedPermissions,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) {
    let raw_path = match &hook_input.tool_input.path {
        Some(p) if !p.is_empty() => p.clone(),
        _ => cwd.to_string(),
    };
    let normalized = path_util::normalize_separators(&raw_path);
    let resolved = file_access::resolve_path(&normalized, cwd);

    let accesses = [FileAccess {
        path: resolved.clone(),
        kind: AccessKind::Read,
    }];
    let result = checker::check_file_accesses(&accesses, parsed_perms, cwd);
    let result = checker::apply_permission_mode(result, permission_mode);

    let log_label = format!("{}({})", hook_input.tool_name, resolved);
    log_and_output(
        agent,
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        &log_label,
        &log_label,
    );
}

/// Handle Read, Write, and Edit tools: check the file path against file rules.
fn handle_file_tool(
    agent: Agent,
    hook_input: &hook::HookInput,
    parsed_perms: &permission::ParsedPermissions,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
    access_kind: AccessKind,
) {
    let raw_path = match &hook_input.tool_input.file_path {
        Some(p) if !p.is_empty() => p.clone(),
        _ => {
            // Synthetic Ask with custom_reason preserves the specific error text
            // through apply_permission_mode (→ allow in bypass/auto, deny in dontAsk).
            let log_label = format!("{}(<missing path>)", hook_input.tool_name);
            let result = CheckResult {
                decision: Decision::Ask,
                matched_allow: vec![],
                matched_deny: vec![],
                missing_rules: vec![log_label.clone()],
                custom_reason: Some(format!(
                    "Missing file path in {} tool input",
                    hook_input.tool_name,
                )),
            };
            let result = checker::apply_permission_mode(result, permission_mode);
            log_and_output(
                agent,
                &result,
                &hook_input.session_id,
                cwd,
                project_root,
                permission_mode,
                &log_label,
                &log_label,
            );
            return;
        }
    };
    let normalized = path_util::normalize_separators(&raw_path);
    let resolved = file_access::resolve_path(&normalized, cwd);

    let accesses = [FileAccess {
        path: resolved.clone(),
        kind: access_kind,
    }];
    let result = checker::check_file_accesses(&accesses, parsed_perms, cwd);
    let result = checker::apply_permission_mode(result, permission_mode);

    let log_label = format!("{}({})", hook_input.tool_name, resolved);
    log_and_output(
        agent,
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        &log_label,
        &log_label,
    );
}

fn handle_apply_patch(
    agent: Agent,
    hook_input: &hook::HookInput,
    parsed_perms: &permission::ParsedPermissions,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) {
    let command = match &hook_input.tool_input.command {
        Some(cmd) if !cmd.is_empty() => cmd.clone(),
        _ => process::exit(0),
    };

    let result = match apply_patch::extract_file_accesses(&command, cwd) {
        Ok(accesses) => checker::check_file_accesses(&accesses, parsed_perms, cwd),
        Err(reason) => CheckResult {
            decision: Decision::Ask,
            matched_allow: vec![],
            matched_deny: vec![],
            missing_rules: vec!["Write(<apply_patch parse error>)".into()],
            custom_reason: Some(reason),
        },
    };
    let result = checker::apply_permission_mode(result, permission_mode);
    log_and_output(
        agent,
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        "apply_patch",
        &command,
    );
}

/// Log the decision and write the JSON output to stdout.
/// `project_root` and `permission_mode` are recorded on every log entry so
/// silent misconfigurations (wrong `CLAUDE_PROJECT_DIR`, missing mode field)
/// are diagnosable from `log.yaml` alone.
#[allow(clippy::too_many_arguments)]
fn log_and_output(
    agent: Agent,
    result: &checker::CheckResult,
    session_id: &str,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
    log_command: &str,
    output_command: &str,
) {
    let mode_str = permission_mode.map(PermissionMode::as_str);
    match &result.decision {
        checker::Decision::Allow => {
            let reason = result
                .custom_reason
                .clone()
                .unwrap_or_else(|| "All commands and file accesses are permitted".to_string());
            logging::log_decision(
                session_id,
                cwd,
                project_root,
                log_command,
                mode_str,
                "allow",
                None,
                &result.matched_allow,
                &[],
                &result.missing_rules,
            );
            output_decision(
                agent,
                "allow",
                &reason,
                output_command,
                result.custom_reason.as_deref(),
            );
        }
        checker::Decision::Deny(reason) => {
            logging::log_decision(
                session_id,
                cwd,
                project_root,
                log_command,
                mode_str,
                "deny",
                Some(reason),
                &result.matched_allow,
                &result.matched_deny,
                // Preserve missing_rules in the log for dontAsk's synthesized Deny
                // (from Ask → Deny transform) so the structured list is grep-friendly.
                // Native denies (a deny rule fired) carry an empty missing_rules, so
                // this is a no-op in that case.
                &result.missing_rules,
            );
            output_decision(agent, "deny", reason, output_command, None);
        }
        checker::Decision::Ask => {
            let reason = result.custom_reason.clone().unwrap_or_else(|| {
                format!(
                    "Missing permission rules: {}",
                    result.missing_rules.join(", ")
                )
            });
            logging::log_decision(
                session_id,
                cwd,
                project_root,
                log_command,
                mode_str,
                "ask",
                None,
                &result.matched_allow,
                &[],
                &result.missing_rules,
            );
            output_decision(agent, "ask", &reason, output_command, None);
        }
    }
}

fn output_decision(
    agent: Agent,
    decision: &str,
    reason: &str,
    command: &str,
    allow_context: Option<&str>,
) {
    match agent {
        Agent::Claude => {
            let output = hook::ClaudeHookOutput::new(decision, reason);
            serde_json::to_writer(io::stdout(), &output).expect("Failed to write output");
        }
        Agent::Codex => match decision {
            "allow" => {
                let output =
                    hook::CodexHookOutput::allow_command_with_context(command, allow_context);
                serde_json::to_writer(io::stdout(), &output).expect("Failed to write output");
            }
            "deny" => {
                let output = hook::CodexHookOutput::deny(reason);
                serde_json::to_writer(io::stdout(), &output).expect("Failed to write output");
            }
            "ask" => {}
            other => unreachable!("Unsupported decision for Codex output: {other}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse_log_filter(args: &[&str]) -> cli::VerdictFilter {
        let mut full_args = vec!["claude-scriptcheck", "log"];
        full_args.extend_from_slice(args);
        let cli = Cli::try_parse_from(full_args).unwrap();
        match cli.command.unwrap() {
            Commands::Log {
                allow,
                no_allow,
                ask,
                no_ask,
                deny,
                no_deny,
                ..
            } => cli::VerdictFilter {
                show_allow: allow || !no_allow,
                show_ask: ask || !no_ask,
                show_deny: deny || !no_deny,
            },
            _ => unreachable!(),
        }
    }

    #[test]
    fn no_flags_shows_all() {
        let f = parse_log_filter(&[]);
        assert!(f.show_allow && f.show_ask && f.show_deny);
    }

    #[test]
    fn no_allow_hides_allow() {
        let f = parse_log_filter(&["--no-allow"]);
        assert!(!f.show_allow);
        assert!(f.show_ask && f.show_deny);
    }

    #[test]
    fn no_ask_hides_ask() {
        let f = parse_log_filter(&["--no-ask"]);
        assert!(f.show_allow && !f.show_ask && f.show_deny);
    }

    #[test]
    fn no_deny_hides_deny() {
        let f = parse_log_filter(&["--no-deny"]);
        assert!(f.show_allow && f.show_ask && !f.show_deny);
    }

    #[test]
    fn allow_flag_shows_allow() {
        let f = parse_log_filter(&["--allow"]);
        assert!(f.show_allow);
    }

    #[test]
    fn no_allow_then_allow_last_wins() {
        let f = parse_log_filter(&["--no-allow", "--allow"]);
        assert!(f.show_allow);
    }

    #[test]
    fn allow_then_no_allow_last_wins() {
        let f = parse_log_filter(&["--allow", "--no-allow"]);
        assert!(!f.show_allow);
    }

    #[test]
    fn multiple_no_flags() {
        let f = parse_log_filter(&["--no-allow", "--no-deny"]);
        assert!(!f.show_allow && f.show_ask && !f.show_deny);
    }

    #[test]
    fn rewrite_hook_command_adds_missing_agent() {
        let binary = std::env::current_exe().unwrap();
        let escaped = binary.to_string_lossy().replace('\'', "'\\''");
        let command = format!("'{escaped}'");
        assert_eq!(
            rewrite_hook_command(&command, Agent::Claude),
            Some(format!("{command} --agent claude"))
        );
    }

    #[test]
    fn rewrite_hook_command_preserves_backslash_separators() {
        // A Windows-style hook command uses `\` separators. The rewrite must
        // parse it (the bash parser would otherwise mangle the backslashes) AND
        // keep the original separators in the output, not rewrite them to `/`.
        let binary = std::env::current_exe().unwrap();
        let backslashed = binary.to_string_lossy().replace('/', "\\");
        let command = format!("'{backslashed}'");
        assert_eq!(
            rewrite_hook_command(&command, Agent::Claude),
            Some(format!("{command} --agent claude")),
        );
    }

    #[test]
    fn rewrite_hook_command_preserves_foreign_agent() {
        assert_eq!(
            rewrite_hook_command("claude-scriptcheck --agent codex", Agent::Claude),
            None
        );
    }

    #[test]
    fn rewrite_hook_command_leaves_matching_agent_unchanged() {
        assert_eq!(
            rewrite_hook_command("claude-scriptcheck --agent=claude", Agent::Claude),
            None
        );
    }

    #[test]
    fn rewrite_hook_command_ignores_non_scriptcheck_commands() {
        assert_eq!(
            rewrite_hook_command("echo claude-scriptcheck", Agent::Claude),
            None
        );
        assert_eq!(
            rewrite_hook_command("env FOO=1 claude-scriptcheck", Agent::Claude),
            None
        );
    }

    #[test]
    fn rewrite_hook_command_ignores_compound_commands() {
        assert_eq!(
            rewrite_hook_command("claude-scriptcheck && echo done", Agent::Claude),
            None
        );
    }

    #[test]
    fn rewrite_hook_command_ignores_scriptcheck_subcommands() {
        assert_eq!(
            rewrite_hook_command("claude-scriptcheck log", Agent::Claude),
            None
        );
        assert_eq!(
            rewrite_hook_command("claude-scriptcheck check claude ls", Agent::Claude),
            None
        );
    }
}
