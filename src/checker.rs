use thaum::ast::*;
use thaum::visit::Visit;

use crate::cmd_parser::{self, CmdParseResult};
use crate::file_access::{self, AccessKind, FileAccess};
use crate::logging;
use crate::permission::{self, ParsedPermissions};

/// Final decision for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask(Vec<String>),
}

/// Top-level entry point: check a parsed program against permission rules.
pub fn check_program(program: &Program, perms: &ParsedPermissions, cwd: &str) -> Decision {
    let mut checker = PermissionChecker {
        perms,
        cwd,
        unmatched: Vec::new(),
        denied: None,
    };
    checker.visit_program(program);

    if let Some(reason) = checker.denied {
        Decision::Deny(reason)
    } else if checker.unmatched.is_empty() {
        Decision::Allow
    } else {
        checker.unmatched.sort();
        checker.unmatched.dedup();
        Decision::Ask(checker.unmatched)
    }
}

struct PermissionChecker<'a> {
    perms: &'a ParsedPermissions,
    cwd: &'a str,
    unmatched: Vec<String>,
    denied: Option<String>,
}

// ─── Visit trait implementation ──────────────────────────────────────────────
//
// Default traversal handles: program → statement → expression → compound → etc.
// We only override the nodes where domain logic lives.

impl<'ast> Visit<'ast> for PermissionChecker<'_> {
    fn visit_command(&mut self, cmd: &'ast Command) {
        if self.denied.is_some() {
            return;
        }
        self.check_command(cmd);
        // Walk arguments for embedded process substitutions / command substitutions.
        // Don't call walk_command — we already handled redirects inside check_command.
        for arg in &cmd.arguments {
            self.visit_argument(arg);
        }
    }

    fn visit_redirect(&mut self, redirect: &'ast Redirect) {
        // Handles redirects for compound / function-def contexts.
        // Command redirects are handled inside check_command.
        if self.denied.is_some() {
            return;
        }
        if let Some(access) = extract_redirect_access(redirect, self.cwd) {
            self.check_file_access(&access);
        }
    }

    fn visit_argument(&mut self, arg: &'ast Argument) {
        if self.denied.is_some() {
            return;
        }
        match arg {
            Argument::Atom(Atom::BashProcessSubstitution { body, .. }) => {
                for stmt in body {
                    self.visit_statement(stmt);
                }
            }
            Argument::Word(w) => {
                self.check_word_command_subs(w);
            }
        }
    }
}

// ─── Domain logic ────────────────────────────────────────────────────────────

impl PermissionChecker<'_> {
    fn deny(&mut self, reason: String) {
        if self.denied.is_none() {
            self.denied = Some(reason);
        }
    }

    fn check_command(&mut self, cmd: &Command) {
        // Assignment-only command (no command name)
        if cmd.arguments.is_empty() {
            return;
        }

        // Extract argument literals
        let arg_literals: Vec<Option<String>> = cmd
            .arguments
            .iter()
            .map(|a| a.try_to_static_string())
            .collect();

        // Get command name
        let cmd_name = match &arg_literals[0] {
            Some(name) => name.clone(),
            None => {
                // Dynamic command name — can't determine identity
                self.unmatched
                    .push("Bash(<dynamic command>)".to_string());
                // Still check redirects
                for redirect in &cmd.redirects {
                    if let Some(access) = extract_redirect_access(redirect, self.cwd) {
                        self.check_file_access(&access);
                    }
                }
                return;
            }
        };

        // eval — always ask
        if cmd_name == "eval" {
            self.unmatched
                .push("Bash(eval ...) -- cannot statically analyze eval".to_string());
            return;
        }

        // Build token list for Bash() rule matching — only static tokens
        let cmd_tokens: Vec<String> = arg_literals
            .iter()
            .take_while(|a| a.is_some())
            .map(|a| a.clone().unwrap())
            .collect();

        // Check against Bash() deny rules first
        for rule in &self.perms.deny_bash {
            if permission::bash_rule_matches(rule, &cmd_tokens) {
                self.deny(format!(
                    "Command '{}' matched deny rule",
                    cmd_tokens.join(" ")
                ));
                return;
            }
        }

        // Check against Bash() allow rules
        let bash_allowed = self
            .perms
            .allow_bash
            .iter()
            .any(|rule| permission::bash_rule_matches(rule, &cmd_tokens));

        // Extract file accesses from redirects
        let redirect_accesses = extract_redirect_accesses(&cmd.redirects, self.cwd);

        // Extract file accesses from well-known command semantics (clap-based parsers)
        let cmd_parse_result =
            cmd_parser::parse_file_accesses(&cmd_name, &arg_literals[1..], self.cwd);
        let (cmd_accesses, parse_failed, inline_script_start) = match cmd_parse_result {
            CmdParseResult::Parsed(cfa) => {
                let script_start = cfa.inline_script_start;
                let accesses = cfa
                    .reads
                    .into_iter()
                    .map(|p| FileAccess {
                        path: p,
                        kind: AccessKind::Read,
                    })
                    .chain(cfa.writes.into_iter().map(|p| FileAccess {
                        path: p,
                        kind: AccessKind::Write,
                    }))
                    .collect::<Vec<_>>();
                (accesses, false, script_start)
            }
            CmdParseResult::ParseFailed {
                cmd_name: cn,
                message,
            } => {
                let cmd_str = cmd_tokens.join(" ");
                logging::log_parse_error(&cmd_str, &cn, &message);
                self.unmatched.push(format!(
                    "Bash({cmd_str}) -- failed to parse arguments for `{cn}`: {message}"
                ));
                (vec![], true, None)
            }
        };

        // Check all file accesses
        for access in redirect_accesses.iter().chain(cmd_accesses.iter()) {
            self.check_file_access(access);
            if self.denied.is_some() {
                return;
            }
        }

        // For file-only commands (mkdir, touch, rm, cp, …), the file access rules are
        // sufficient — no separate Bash() rule is needed, provided:
        //   1. the command has at least one resolved file access to gate it,
        //   2. all arguments are static (no dynamic args that could hide unchecked paths), and
        //   3. the parser didn't fail (we trust the extracted accesses).
        if !bash_allowed && !parse_failed {
            let has_file_accesses = !redirect_accesses.is_empty() || !cmd_accesses.is_empty();
            let has_dynamic_args = arg_literals[1..].iter().any(|a| a.is_none());
            let can_skip = file_access::is_file_only_command(&cmd_name)
                && has_file_accesses
                && !has_dynamic_args;

            if !can_skip {
                let rule = if let Some(idx) = inline_script_start {
                    // Truncate before the inline script text, append wildcard.
                    // idx is 0-based into args (without cmd name), so in
                    // cmd_tokens (which has cmd name at [0]) it maps to idx+1.
                    let end = (idx + 1).min(cmd_tokens.len());
                    format!("Bash({} *)", cmd_tokens[..end].join(" "))
                } else {
                    format!("Bash({})", cmd_tokens.join(" "))
                };
                self.unmatched.push(rule);
            }
        }
    }

    /// Check file access against Read/Write/Edit rules.
    fn check_file_access(&mut self, access: &FileAccess) {
        if self.denied.is_some() {
            return;
        }

        // Check deny first
        let denied = match access.kind {
            AccessKind::Read => self
                .perms
                .deny_read
                .iter()
                .any(|pat| permission::file_rule_matches(pat, &access.path)),
            AccessKind::Write => {
                self.perms
                    .deny_write
                    .iter()
                    .any(|pat| permission::file_rule_matches(pat, &access.path))
                    || self
                        .perms
                        .deny_edit
                        .iter()
                        .any(|pat| permission::file_rule_matches(pat, &access.path))
            }
        };
        if denied {
            self.deny(format!(
                "File access '{}' ({:?}) matched deny rule",
                access.path, access.kind
            ));
            return;
        }

        // Check allow
        let allowed = match access.kind {
            AccessKind::Read => self
                .perms
                .allow_read
                .iter()
                .any(|pat| permission::file_rule_matches(pat, &access.path)),
            AccessKind::Write => {
                self.perms
                    .allow_write
                    .iter()
                    .any(|pat| permission::file_rule_matches(pat, &access.path))
                    || self
                        .perms
                        .allow_edit
                        .iter()
                        .any(|pat| permission::file_rule_matches(pat, &access.path))
            }
        };
        if !allowed {
            let rule_needed = match access.kind {
                AccessKind::Read => format!("Read({})", access.path),
                AccessKind::Write => format!("Write({})", access.path),
            };
            self.unmatched.push(rule_needed);
        }
    }

    /// Walk word fragments for command substitutions.
    fn check_word_command_subs(&mut self, word: &Word) {
        for fragment in &word.parts {
            self.check_fragment_command_subs(fragment);
        }
    }

    fn check_fragment_command_subs(&mut self, fragment: &Fragment) {
        if self.denied.is_some() {
            return;
        }
        match fragment {
            Fragment::CommandSubstitution(stmts) => {
                for stmt in stmts {
                    self.visit_statement(stmt);
                }
            }
            Fragment::DoubleQuoted(inner) => {
                for f in inner {
                    self.check_fragment_command_subs(f);
                }
            }
            _ => {}
        }
    }
}

// ─── Redirect file access extraction ─────────────────────────────────────────

fn extract_redirect_access(redirect: &Redirect, cwd: &str) -> Option<FileAccess> {
    let (word, kind) = match &redirect.kind {
        RedirectKind::Input(w) => (Some(w), AccessKind::Read),
        RedirectKind::Output(w) | RedirectKind::Clobber(w) => (Some(w), AccessKind::Write),
        RedirectKind::Append(w) => (Some(w), AccessKind::Write),
        RedirectKind::ReadWrite(w) => (Some(w), AccessKind::Write),
        RedirectKind::BashOutputAll(w) | RedirectKind::BashAppendAll(w) => {
            (Some(w), AccessKind::Write)
        }
        RedirectKind::HereDoc { .. } | RedirectKind::BashHereString(_) => return None,
        RedirectKind::DupInput(_) | RedirectKind::DupOutput(_) => return None,
    };

    let word = word?;
    let path = word.try_to_static_string()?;
    // Skip /dev/* special files
    if path.starts_with("/dev/") {
        return None;
    }
    Some(FileAccess {
        path: file_access::resolve_path(&path, cwd),
        kind,
    })
}

fn extract_redirect_accesses(redirects: &[Redirect], cwd: &str) -> Vec<FileAccess> {
    redirects
        .iter()
        .filter_map(|r| extract_redirect_access(r, cwd))
        .collect()
}
