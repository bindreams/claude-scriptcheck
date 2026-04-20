use std::io::{self, Read};
use std::process;

use clap::{Parser, Subcommand};
use claude_scriptcheck::checker::{CheckResult, Decision};
use claude_scriptcheck::file_access::{self, AccessKind, FileAccess};
use claude_scriptcheck::permission_mode::PermissionMode;
use claude_scriptcheck::{checker, cli, hook, logging, path_util, permission};

#[derive(Parser)]
#[command(
    name = "claude-scriptcheck",
    about = "Permission checker for Claude Code hooks"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the hook in Claude settings
    Install {
        /// Install to project-level settings instead of global
        #[arg(long)]
        project: bool,
    },
    /// Uninstall the hook from Claude settings
    Uninstall {
        /// Uninstall from project-level settings instead of global
        #[arg(long)]
        project: bool,
    },
    /// Manually check a command against the permission rules
    Check {
        /// The shell command to check
        command: String,
        /// Working directory context (defaults to current dir)
        #[arg(long, default_value = ".")]
        cwd: String,
        /// Simulate a specific permission mode
        #[arg(long, value_enum)]
        permission_mode: Option<PermissionMode>,
    },
    /// Print the decision log
    Log {
        /// Clear the log after printing
        #[arg(long)]
        clear: bool,
        /// Follow new log entries (like tail -f)
        #[arg(long, alias = "watch", conflicts_with = "clear")]
        follow: bool,
        /// Show only the last N entries
        #[arg(long)]
        tail: Option<usize>,
        /// Show allow verdicts (use --no-allow to hide)
        #[arg(long, overrides_with = "no_allow")]
        allow: bool,
        #[arg(long, overrides_with = "allow", hide = true)]
        no_allow: bool,
        /// Show ask verdicts (use --no-ask to hide)
        #[arg(long, overrides_with = "no_ask")]
        ask: bool,
        #[arg(long, overrides_with = "ask", hide = true)]
        no_ask: bool,
        /// Show deny verdicts (use --no-deny to hide)
        #[arg(long, overrides_with = "no_deny")]
        deny: bool,
        #[arg(long, overrides_with = "deny", hide = true)]
        no_deny: bool,
    },
    /// Print the path to the log file
    LogPath,
    /// Upgrade claude-scriptcheck to the latest version
    Upgrade,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Install { project }) => cli::install(project),
        Some(Commands::Uninstall { project }) => cli::uninstall(project),
        Some(Commands::Check {
            command,
            cwd,
            permission_mode,
        }) => cli::check(&command, &cwd, permission_mode),
        Some(Commands::Log {
            clear, follow, tail, allow, no_allow, ask, no_ask, deny, no_deny,
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
        None => run_hook(),
    }
}

/// Hook mode: reads JSON from stdin, outputs JSON to stdout.
/// This is the default when invoked with no subcommand (i.e., by Claude Code).
fn run_hook() {
    let mut input_str = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input_str) {
        eprintln!("Failed to read stdin: {e}");
        process::exit(2);
    }

    let hook_input: hook::HookInput = match serde_json::from_str(&input_str) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to parse hook input: {e}");
            process::exit(2);
        }
    };

    // Normalize path separators (Windows backslashes → forward slashes).
    let cwd = path_util::normalize_separators(&hook_input.cwd);
    let project_root = std::env::var("CLAUDE_PROJECT_DIR")
        .map(|s| path_util::normalize_separators(&s))
        .unwrap_or_else(|_| cwd.clone());
    let permission_mode = PermissionMode::from_hook_str(hook_input.permission_mode.as_deref());

    match hook_input.tool_name.as_str() {
        "Bash" | "Monitor" => handle_bash(&hook_input, &cwd, &project_root, permission_mode),
        "Grep" | "Glob" => handle_file_search(&hook_input, &cwd, &project_root, permission_mode),
        "Read" => handle_file_tool(
            &hook_input,
            &cwd,
            &project_root,
            permission_mode,
            AccessKind::Read,
        ),
        "Write" | "Edit" => handle_file_tool(
            &hook_input,
            &cwd,
            &project_root,
            permission_mode,
            AccessKind::Write,
        ),
        _ => process::exit(0),
    }
}

/// Handle the Bash tool: parse the command with thaum and walk the AST.
fn handle_bash(
    hook_input: &hook::HookInput,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
) {
    let command = match &hook_input.tool_input.command {
        Some(cmd) if !cmd.is_empty() => cmd.clone(),
        _ => process::exit(0),
    };

    let parsed_perms = permission::load_perms(cwd, project_root, permission_mode);

    // Parse the bash command with thaum. On parse failure, construct a synthetic
    // Ask result with custom_reason so the original error message is preserved
    // through the apply_permission_mode transform.
    let result = match thaum::parse_with(&command, thaum::Dialect::Bash) {
        Ok(program) => checker::check_program(&program, &parsed_perms, cwd),
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
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        &command,
    );
}

/// Handle Grep and Glob tools: check the search path against Read rules.
fn handle_file_search(
    hook_input: &hook::HookInput,
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

    let parsed_perms = permission::load_perms(cwd, project_root, permission_mode);
    let accesses = [FileAccess {
        path: resolved.clone(),
        kind: AccessKind::Read,
    }];
    let result = checker::check_file_accesses(&accesses, &parsed_perms, cwd);
    let result = checker::apply_permission_mode(result, permission_mode);

    let log_label = format!("{}({})", hook_input.tool_name, resolved);
    log_and_output(
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        &log_label,
    );
}

/// Handle Read, Write, and Edit tools: check the file path against file rules.
fn handle_file_tool(
    hook_input: &hook::HookInput,
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
                &result,
                &hook_input.session_id,
                cwd,
                project_root,
                permission_mode,
                &log_label,
            );
            return;
        }
    };
    let normalized = path_util::normalize_separators(&raw_path);
    let resolved = file_access::resolve_path(&normalized, cwd);

    let parsed_perms = permission::load_perms(cwd, project_root, permission_mode);
    let accesses = [FileAccess {
        path: resolved.clone(),
        kind: access_kind,
    }];
    let result = checker::check_file_accesses(&accesses, &parsed_perms, cwd);
    let result = checker::apply_permission_mode(result, permission_mode);

    let log_label = format!("{}({})", hook_input.tool_name, resolved);
    log_and_output(
        &result,
        &hook_input.session_id,
        cwd,
        project_root,
        permission_mode,
        &log_label,
    );
}

/// Log the decision and write the JSON output to stdout.
/// `project_root` and `permission_mode` are recorded on every log entry so
/// silent misconfigurations (wrong `CLAUDE_PROJECT_DIR`, missing mode field)
/// are diagnosable from `log.yaml` alone.
fn log_and_output(
    result: &checker::CheckResult,
    session_id: &str,
    cwd: &str,
    project_root: &str,
    permission_mode: Option<PermissionMode>,
    command: &str,
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
                command,
                mode_str,
                "allow",
                None,
                &result.matched_allow,
                &[],
                &result.missing_rules,
            );
            output_decision("allow", &reason);
        }
        checker::Decision::Deny(reason) => {
            logging::log_decision(
                session_id,
                cwd,
                project_root,
                command,
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
            output_decision("deny", reason);
        }
        checker::Decision::Ask => {
            let reason = result.custom_reason.clone().unwrap_or_else(|| {
                format!("Missing permission rules: {}", result.missing_rules.join(", "))
            });
            logging::log_decision(
                session_id,
                cwd,
                project_root,
                command,
                mode_str,
                "ask",
                None,
                &result.matched_allow,
                &[],
                &result.missing_rules,
            );
            output_decision("ask", &reason);
        }
    }
}

fn output_decision(decision: &str, reason: &str) {
    let output = hook::HookOutput::new(decision, reason);
    serde_json::to_writer(io::stdout(), &output).expect("Failed to write output");
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
            Commands::Log { allow, no_allow, ask, no_ask, deny, no_deny, .. } => {
                cli::VerdictFilter {
                    show_allow: allow || !no_allow,
                    show_ask: ask || !no_ask,
                    show_deny: deny || !no_deny,
                }
            }
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
}
