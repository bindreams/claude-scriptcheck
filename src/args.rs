use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::permission_mode::PermissionMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "claude-scriptcheck",
    about = "Permission checker for Claude Code and Codex hooks",
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[arg(long, value_enum)]
    pub agent: Option<Agent>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

impl Cli {
    pub fn parse_and_validate() -> Self {
        match Self::parse().validate() {
            Ok(cli) => cli,
            Err(err) => err.exit(),
        }
    }

    pub fn validate(self) -> Result<Self, clap::Error> {
        if self.command.is_none() && self.agent.is_none() {
            return Err(Self::missing_agent_error());
        }

        Ok(self)
    }

    pub fn missing_agent_error() -> clap::Error {
        Self::command().error(
            ErrorKind::MissingRequiredArgument,
            "the following required arguments were not provided:\n  --agent <AGENT>",
        )
    }
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Install the hook in settings
    Install {
        agent: Agent,
        /// Install to project-level settings instead of global
        #[arg(long)]
        project: bool,
    },
    /// Uninstall the hook from settings
    Uninstall {
        agent: Agent,
        /// Uninstall from project-level settings instead of global
        #[arg(long)]
        project: bool,
    },
    /// Manually check a command against the permission rules
    Check {
        agent: Agent,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn install_accepts_positional_agent() {
        let cli = Cli::try_parse_from(["claude-scriptcheck", "install", "codex"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Install {
                agent: Agent::Codex,
                project: false,
            })
        ));
    }

    #[test]
    fn check_accepts_positional_agent() {
        let cli = Cli::try_parse_from(["claude-scriptcheck", "check", "claude", "ls"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Check {
                agent: Agent::Claude,
                command,
                ..
            }) if command == "ls"
        ));
    }

    #[test]
    fn top_level_agent_rejected_with_subcommand() {
        let result = Cli::try_parse_from([
            "claude-scriptcheck",
            "--agent",
            "claude",
            "install",
            "codex",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_requires_agent_without_subcommand() {
        let cli = Cli::try_parse_from(["claude-scriptcheck"]).unwrap();
        let err = cli.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--agent <AGENT>"));
    }

    #[test]
    fn validate_allows_hook_mode_with_top_level_agent() {
        let cli = Cli::try_parse_from(["claude-scriptcheck", "--agent", "claude"])
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(cli.agent, Some(Agent::Claude));
        assert!(cli.command.is_none());
    }
}
