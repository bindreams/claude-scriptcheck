#[path = "suite/canonicalize.rs"]
mod canonicalize;
#[path = "suite/checker.rs"]
mod checker;
#[path = "suite/cli.rs"]
mod cli;
#[path = "suite/cmd_parser.rs"]
mod cmd_parser;
#[path = "suite/file_access.rs"]
mod file_access;
#[path = "suite/integration.rs"]
mod integration;
#[path = "suite/path_util.rs"]
mod path_util;
#[path = "suite/permission.rs"]
mod permission;
#[path = "suite/repo_infra.rs"]
mod repo_infra;
#[path = "suite/settings.rs"]
mod settings;

fn main() {
    skuld::run_all()
}
