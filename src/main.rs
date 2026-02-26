use std::io::{self, Read};
use std::process;

use clap::{Parser, Subcommand};
use claude_scriptcheck::{checker, cli, hook, logging, permission, settings};

#[derive(Parser)]
#[command(name = "claude-scriptcheck", about = "AST-aware Bash permission checker for Claude Code hooks")]
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
    },
    /// Print the decision log
    Log {
        /// Clear the log after printing
        #[arg(long)]
        clear: bool,
        /// Watch for new log entries (like tail -f)
        #[arg(long, conflicts_with = "clear")]
        watch: bool,
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
        Some(Commands::Check { command, cwd }) => cli::check(&command, &cwd),
        Some(Commands::Log { clear, watch }) => cli::log(clear, watch),
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

    // Only handle Bash tool
    if hook_input.tool_name != "Bash" {
        process::exit(0);
    }

    let command = match &hook_input.tool_input.command {
        Some(cmd) if !cmd.is_empty() => cmd.clone(),
        _ => process::exit(0),
    };

    // Load and merge settings
    let permissions = settings::load_settings(&hook_input.cwd);
    let parsed_perms = permission::parse_rules(&permissions);

    // Parse the bash command with thaum
    let program = match thaum::parse_with(&command, thaum::Dialect::Bash) {
        Ok(p) => p,
        Err(_) => {
            logging::log_decision(
                &hook_input.session_id,
                &hook_input.cwd,
                &command,
                "ask",
                None,
                &[],
                &[],
                &["Bash(<parse error>)".to_string()],
            );
            output_decision("ask", "Shell command could not be parsed");
            process::exit(0);
        }
    };

    // Check permissions
    let result = checker::check_program(&program, &parsed_perms, &hook_input.cwd);

    match &result.decision {
        checker::Decision::Allow => {
            logging::log_decision(
                &hook_input.session_id,
                &hook_input.cwd,
                &command,
                "allow",
                None,
                &result.matched_allow,
                &[],
                &[],
            );
            output_decision("allow", "All commands and file accesses are permitted");
        }
        checker::Decision::Deny(reason) => {
            logging::log_decision(
                &hook_input.session_id,
                &hook_input.cwd,
                &command,
                "deny",
                Some(reason),
                &result.matched_allow,
                &result.matched_deny,
                &[],
            );
            output_decision("deny", reason);
        }
        checker::Decision::Ask(missing) => {
            let reason = format!("Missing permission rules: {}", missing.join(", "));
            logging::log_decision(
                &hook_input.session_id,
                &hook_input.cwd,
                &command,
                "ask",
                None,
                &result.matched_allow,
                &[],
                missing,
            );
            output_decision("ask", &reason);
        }
    }
}

fn output_decision(decision: &str, reason: &str) {
    let output = hook::HookOutput::new(decision, reason);
    serde_json::to_writer(io::stdout(), &output).expect("Failed to write output");
}
