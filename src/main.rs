use std::io::{self, Read};
use std::process;

use clap::{Parser, Subcommand};

mod checker;
mod cli;
mod file_access;
mod hook;
mod logging;
mod permission;
mod settings;
mod word_util;

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
    /// Print the missing-rules log
    Log {
        /// Clear the log after printing
        #[arg(long)]
        clear: bool,
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
        Some(Commands::Log { clear }) => cli::log(clear),
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
            output_decision("ask", "Shell command could not be parsed");
            process::exit(0);
        }
    };

    // Check permissions
    let decision = checker::check_program(&program, &parsed_perms, &hook_input.cwd);

    match decision {
        checker::Decision::Allow => {
            output_decision("allow", "All commands and file accesses are permitted");
        }
        checker::Decision::Deny(reason) => {
            output_decision("deny", &reason);
        }
        checker::Decision::Ask(missing) => {
            let reason = format!("Missing permission rules: {}", missing.join(", "));
            logging::log_missing_rules(&missing, &command);
            output_decision("ask", &reason);
        }
    }
}

fn output_decision(decision: &str, reason: &str) {
    let output = hook::HookOutput::new(decision, reason);
    serde_json::to_writer(io::stdout(), &output).expect("Failed to write output");
}
