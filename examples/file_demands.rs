//! Print the file accesses a shell command implies, one line per command.
//!
//! Support for `scripts/redirect-differential.py`, which compares these against
//! what real bash does. Reads NUL-separated commands from a file and writes
//! `<command>\t<demand>\u{1f}<demand>…`, using empty permissions so every
//! access the checker derives shows up as a missing rule.
//!
//! ```sh
//! cargo run --example file_demands -- <cwd> <commands-file>
//! ```
use claude_scriptcheck::checker::check_program;
use claude_scriptcheck::permission;
use claude_scriptcheck::settings::Permissions;

fn main() {
    let mut args = std::env::args().skip(1);
    let cwd = args
        .next()
        .expect("usage: file_demands <cwd> <commands-file>");
    let path = args
        .next()
        .expect("usage: file_demands <cwd> <commands-file>");
    let perms = permission::parse_rules(&Permissions::default(), &cwd, &cwd);
    let body = std::fs::read_to_string(path).unwrap();
    for cmd in body.split('\0').filter(|c| !c.is_empty()) {
        let demands = match thaum::parse_with(cmd, thaum::Dialect::Bash) {
            Ok(program) => check_program(&program, cmd, &perms, &cwd)
                .missing_rules
                .join("\u{1f}"),
            Err(_) => "<parse-error>".to_string(),
        };
        println!("{}\t{}", cmd.replace('\t', "\\t"), demands);
    }
}
