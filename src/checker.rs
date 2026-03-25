use thaum::ast::*;
use thaum::visit::Visit;

use crate::cmd_parser::{self, CmdParseResult};
use crate::file_access::{self, AccessKind, FileAccess};
use crate::permission::{self, ParsedPermissions};
use crate::python_ast::{self, PythonAnalysis};

/// Final decision for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask(Vec<String>),
}

/// Full result of checking a program, including which rules matched.
pub struct CheckResult {
    pub decision: Decision,
    /// Allow rules that matched (Bash, Read, Write, Edit).
    pub matched_allow: Vec<String>,
    /// Deny rules that matched (at most one in practice).
    pub matched_deny: Vec<String>,
}

/// Top-level entry point: check a parsed program against permission rules.
pub fn check_program(program: &Program, perms: &ParsedPermissions, cwd: &str) -> CheckResult {
    let mut checker = PermissionChecker {
        perms,
        cwd,
        unmatched: Vec::new(),
        denied: None,
        matched_allow: Vec::new(),
        matched_deny: Vec::new(),
    };
    checker.visit_program(program);
    checker.finalize()
}

/// Check file accesses against permission rules, without parsing bash.
/// Used for non-Bash tools (Read, Write, Edit, Grep, Glob).
pub fn check_file_accesses(
    accesses: &[FileAccess],
    perms: &ParsedPermissions,
    cwd: &str,
) -> CheckResult {
    let mut checker = PermissionChecker {
        perms,
        cwd,
        unmatched: Vec::new(),
        denied: None,
        matched_allow: Vec::new(),
        matched_deny: Vec::new(),
    };
    for access in accesses {
        checker.check_file_access(access);
        if checker.denied.is_some() {
            break;
        }
    }
    checker.finalize()
}

struct PermissionChecker<'a> {
    perms: &'a ParsedPermissions,
    cwd: &'a str,
    unmatched: Vec<String>,
    denied: Option<String>,
    matched_allow: Vec<String>,
    matched_deny: Vec<String>,
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
    fn finalize(mut self) -> CheckResult {
        let decision = if let Some(reason) = self.denied {
            Decision::Deny(reason)
        } else if self.unmatched.is_empty() {
            Decision::Allow
        } else {
            self.unmatched.sort();
            self.unmatched.dedup();
            Decision::Ask(self.unmatched)
        };

        self.matched_allow.sort();
        self.matched_allow.dedup();
        self.matched_deny.sort();
        self.matched_deny.dedup();

        CheckResult {
            decision,
            matched_allow: self.matched_allow,
            matched_deny: self.matched_deny,
        }
    }

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
                self.unmatched.push("Bash(<dynamic command>)".to_string());
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
                self.matched_deny.push(rule.to_rule_string());
                self.deny(format!(
                    "Command '{}' matched deny rule",
                    cmd_tokens.join(" ")
                ));
                return;
            }
        }

        // Check against Bash() ask rules — force ask even if allowed
        let bash_asked = self
            .perms
            .ask_bash
            .iter()
            .any(|rule| permission::bash_rule_matches(rule, &cmd_tokens));

        // Check against Bash() allow rules (skip if ask matched)
        let bash_allowed = !bash_asked
            && self.perms.allow_bash.iter().any(|rule| {
                let matched = permission::bash_rule_matches(rule, &cmd_tokens);
                if matched {
                    self.matched_allow.push(rule.to_rule_string());
                }
                matched
            });

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
                self.unmatched.push(format!(
                    "Bash({cmd_str}) -- failed to parse arguments for `{cn}`: {message}"
                ));
                (vec![], true, None)
            }
        };

        // Attempt Python AST analysis for python -c inline scripts.
        // If the script can be fully analyzed, its file accesses are appended to
        // cmd_accesses and the Bash() rule requirement is suppressed.
        let mut python_analyzed = false;
        let mut cmd_accesses = cmd_accesses;
        if matches!(cmd_name.as_str(), "python" | "python3") && !bash_asked {
            if let Some(script_idx) = inline_script_start {
                // inline_script_start is 0-based into args-after-cmd-name.
                // arg_literals[0] is the cmd name, so script text is at [script_idx + 1].
                if let Some(Some(script_text)) = arg_literals.get(script_idx + 1) {
                    if let PythonAnalysis::Analyzed { accesses } =
                        python_ast::analyze_python_script(script_text, self.cwd)
                    {
                        cmd_accesses.extend(accesses);
                        python_analyzed = true;
                    }
                }
            }
        }

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
        // Similarly, when Python AST analysis succeeded, the Bash() rule is suppressed.
        if !bash_allowed && !parse_failed {
            let has_file_accesses = !redirect_accesses.is_empty() || !cmd_accesses.is_empty();
            let has_dynamic_args = arg_literals[1..].iter().any(|a| a.is_none());
            let can_skip = (file_access::is_file_only_command(&cmd_name)
                && has_file_accesses
                && !has_dynamic_args
                && !bash_asked)
                || (python_analyzed && !bash_asked);

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

        // Canonicalize the query path before matching against rules
        let path = crate::canonicalize::best_effort_canonicalize(&access.path);

        // Check deny first
        let deny_matched = match access.kind {
            AccessKind::Read => self
                .perms
                .deny_read
                .iter()
                .find(|pat| permission::file_rule_matches(pat, &path))
                .map(|pat| format!("Read({pat})")),
            AccessKind::Write => self
                .perms
                .deny_write
                .iter()
                .find(|pat| permission::file_rule_matches(pat, &path))
                .map(|pat| format!("Write({pat})"))
                .or_else(|| {
                    self.perms
                        .deny_edit
                        .iter()
                        .find(|pat| permission::file_rule_matches(pat, &path))
                        .map(|pat| format!("Edit({pat})"))
                }),
        };
        if let Some(rule_str) = deny_matched {
            self.matched_deny.push(rule_str);
            self.deny(format!(
                "File access '{}' ({:?}) matched deny rule",
                path, access.kind
            ));
            return;
        }

        // Check ask rules — force ask even if allowed
        let ask_matched = match access.kind {
            AccessKind::Read => self
                .perms
                .ask_read
                .iter()
                .any(|pat| permission::file_rule_matches(pat, &path)),
            AccessKind::Write => {
                self.perms
                    .ask_write
                    .iter()
                    .any(|pat| permission::file_rule_matches(pat, &path))
                    || self
                        .perms
                        .ask_edit
                        .iter()
                        .any(|pat| permission::file_rule_matches(pat, &path))
            }
        };
        if ask_matched {
            let rule_needed = match access.kind {
                AccessKind::Read => format!("Read({path})"),
                AccessKind::Write => format!("Write({path})"),
            };
            self.unmatched.push(rule_needed);
            return;
        }

        // Check allow
        let allow_matched = match access.kind {
            AccessKind::Read => self
                .perms
                .allow_read
                .iter()
                .find(|pat| permission::file_rule_matches(pat, &path))
                .map(|pat| format!("Read({pat})")),
            AccessKind::Write => self
                .perms
                .allow_write
                .iter()
                .find(|pat| permission::file_rule_matches(pat, &path))
                .map(|pat| format!("Write({pat})"))
                .or_else(|| {
                    self.perms
                        .allow_edit
                        .iter()
                        .find(|pat| permission::file_rule_matches(pat, &path))
                        .map(|pat| format!("Edit({pat})"))
                }),
        };
        if let Some(rule_str) = allow_matched {
            self.matched_allow.push(rule_str);
        } else {
            let rule_needed = match access.kind {
                AccessKind::Read => format!("Read({path})"),
                AccessKind::Write => format!("Write({path})"),
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
