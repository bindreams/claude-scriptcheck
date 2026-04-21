use thaum::ast::*;
use thaum::visit::Visit;

use crate::cmd_parser::{self, CmdParseResult};
use crate::file_access::{self, AccessKind, FileAccess};
use crate::filter::{BashFilter, Filter, PathFilter};
use crate::permission::ParsedPermissions;
use crate::permission_mode::PermissionMode;
use crate::python_ast::{self, PythonAnalysis};

/// Final decision for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask,
}

/// Full result of checking a program, including which rules matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub decision: Decision,
    /// Allow rules that matched (Bash, Read, Write, Edit).
    pub matched_allow: Vec<String>,
    /// Deny rules that matched (at most one in practice).
    pub matched_deny: Vec<String>,
    /// Rules that would need to be allowed for the decision to be Allow.
    /// Populated whenever at least one rule went unmatched, regardless of the final
    /// decision. Surviving the `apply_permission_mode` transform is the point:
    /// after Ask → Allow in bypass/auto, the log can still show what was missing.
    pub missing_rules: Vec<String>,
    /// Optional override for the user-facing reason text in `log_and_output`.
    /// Used by synthetic Ask sites (parse failures, missing file paths) to preserve
    /// their informative reason across the `apply_permission_mode` transform.
    pub custom_reason: Option<String>,
}

/// Transform a `CheckResult`'s decision based on the active permission mode.
///
/// Applied at the **end** of the decision pipeline. Only `Decision::Ask` is
/// transformed: in `BypassPermissions` / `Auto` it becomes `Allow`; in `DontAsk`
/// it becomes `Deny`. `Allow` and `Deny` pass through unchanged in every mode —
/// a deny rule is authoritative everywhere, including bypass, matching Claude
/// Code's own documented behavior for hook-deny.
///
/// `missing_rules` on the result is preserved regardless of outcome, so the log
/// can still record what was unmatched even when the final verdict is Allow.
pub fn apply_permission_mode(mut result: CheckResult, mode: Option<PermissionMode>) -> CheckResult {
    use PermissionMode::*;
    let decision = std::mem::replace(&mut result.decision, Decision::Allow);
    result.decision = match (decision, mode) {
        (Decision::Ask, Some(BypassPermissions | Auto)) => Decision::Allow,
        (Decision::Ask, Some(DontAsk)) => {
            let missing = if result.missing_rules.is_empty() {
                // Invariant ordinarily holds via `finalize()`, but guard anyway so
                // release builds emit a coherent reason if a synthetic `CheckResult`
                // is ever constructed with an empty `missing_rules`.
                "<unspecified rule>".to_string()
            } else {
                result.missing_rules.join(", ")
            };
            let base = format!(
                "dontAsk mode: command requires rule(s) not in settings: {missing}. \
                 Add the listed rule(s) to permissions.allow to run this.",
            );
            // Preserve custom_reason context (e.g. "Shell command could not be parsed")
            // by prefixing it — the deny payload becomes the source of truth for the
            // final reason, since Decision::Deny's reason is always shown to the user.
            let reason = match &result.custom_reason {
                Some(ctx) if !ctx.is_empty() => format!("{ctx}. {base}"),
                _ => base,
            };
            Decision::Deny(reason)
        }
        (other, _) => other,
    };
    result
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
        self.unmatched.sort();
        self.unmatched.dedup();
        let decision = if let Some(reason) = self.denied {
            Decision::Deny(reason)
        } else if self.unmatched.is_empty() {
            Decision::Allow
        } else {
            Decision::Ask
        };

        self.matched_allow.sort();
        self.matched_allow.dedup();
        self.matched_deny.sort();
        self.matched_deny.dedup();

        CheckResult {
            decision,
            missing_rules: self.unmatched,
            custom_reason: None,
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

        // Get command name (normalized: basename, no .exe suffix)
        let cmd_name = match &arg_literals[0] {
            Some(name) => cmd_parser::normalize_cmd_name(name).to_string(),
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

        // Build token list for Bash() rule matching — only static tokens.
        // The first token uses the normalized command name so rules like
        // `Bash(python3 *)` match `/usr/bin/python3 script.py`.
        let cmd_tokens: Vec<String> = std::iter::once(cmd_name.clone())
            .chain(
                arg_literals[1..]
                    .iter()
                    .take_while(|a| a.is_some())
                    .map(|a| a.clone().unwrap()),
            )
            .collect();

        // Check against Bash() deny rules first
        for filter in &self.perms.bash.deny {
            if filter.matches(&cmd_tokens) {
                self.matched_deny.push(filter.to_rule_string());
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
            .bash
            .ask
            .iter()
            .any(|filter| filter.matches(&cmd_tokens));

        // Check against Bash() allow rules (skip if ask matched)
        let bash_allowed = !bash_asked
            && self.perms.bash.allow.iter().any(|filter| {
                let matched = filter.matches(&cmd_tokens);
                if matched {
                    self.matched_allow.push(filter.to_rule_string());
                }
                matched
            });

        // Extract file accesses from redirects
        let redirect_accesses = extract_redirect_accesses(&cmd.redirects, self.cwd);

        // Extract file accesses from well-known command semantics (clap-based parsers)
        let cmd_parse_result =
            cmd_parser::parse_file_accesses(&cmd_name, &arg_literals[1..], self.cwd);
        let (cmd_accesses, parse_failed, inline_script_start, file_only_override, effective_cmd) =
            match cmd_parse_result {
                CmdParseResult::Parsed(cfa) => {
                    let script_start = cfa.inline_script_start;
                    let file_only = cfa.file_only;
                    let eff = cfa.effective_cmd_name;
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
                    (accesses, false, script_start, file_only, eff)
                }
                CmdParseResult::ParseFailed {
                    cmd_name: cn,
                    message,
                } => {
                    let cmd_str = cmd_tokens.join(" ");
                    self.unmatched.push(format!(
                        "Bash({cmd_str}) -- failed to parse arguments for `{cn}`: {message}"
                    ));
                    (vec![], true, None, None, None)
                }
            };

        // The effective command name for Python analysis and is_file_only_command.
        // For wrapper commands like `uv run python -c ...`, this is `python`.
        let effective = effective_cmd.as_deref().unwrap_or(&cmd_name);

        // Attempt Python AST analysis for python -c inline scripts.
        // If the script can be fully analyzed, its file accesses are appended to
        // cmd_accesses and the Bash() rule requirement is suppressed.
        let mut python_analyzed = false;
        let mut cmd_accesses = cmd_accesses;
        if cmd_parser::is_python_cmd(effective) && !bash_asked {
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
            let can_skip = match file_only_override {
                // Parser explicitly declared this invocation's effects.
                // Trust it even with zero file accesses (e.g. read-only git
                // subcommands), but still require static args.
                Some(true) => !has_dynamic_args && !bash_asked,
                // Parser says there are non-file side effects (e.g. network).
                Some(false) => false,
                // Legacy path: use is_file_only_command() and require at
                // least one file access as a guard.
                None => {
                    file_access::is_file_only_command(effective)
                        && has_file_accesses
                        && !has_dynamic_args
                        && !bash_asked
                }
            } || (python_analyzed && !bash_asked);

            if !can_skip {
                let filter = if let Some(idx) = inline_script_start {
                    // Truncate before the inline script text, append wildcard.
                    // idx is 0-based into args (without cmd name), so in
                    // cmd_tokens (which has cmd name at [0]) it maps to idx+1.
                    let end = (idx + 1).min(cmd_tokens.len());
                    BashFilter::new_wildcard(cmd_tokens[..end].to_vec())
                } else {
                    BashFilter::new(cmd_tokens.clone())
                };
                self.unmatched.push(filter.to_rule_string());
            }
        }
    }

    /// Check file access against Read/Write/Edit rules.
    ///
    /// Edit-over-Write fallback: for `AccessKind::Write`, each bucket (deny, ask,
    /// allow) is tested first against `write.<bucket>` and then against
    /// `edit.<bucket>`. `Edit(pat)` therefore also allows/denies/asks writes —
    /// but not vice versa. The fallback is an intentional asymmetry; see
    /// CLAUDE.md conventions.
    fn check_file_access(&mut self, access: &FileAccess) {
        if self.denied.is_some() {
            return;
        }

        // Canonicalize the query path before matching against rules
        let path = crate::canonicalize::best_effort_canonicalize(&access.path);

        // Check deny first (Edit fallback for Write)
        let deny_matched: Option<String> = match access.kind {
            AccessKind::Read => find_match(&self.perms.read.deny, &path),
            AccessKind::Write => find_match(&self.perms.write.deny, &path)
                .or_else(|| find_match(&self.perms.edit.deny, &path)),
        };
        if let Some(rule_str) = deny_matched {
            self.matched_deny.push(rule_str);
            self.deny(format!(
                "File access '{}' ({:?}) matched deny rule",
                path, access.kind
            ));
            return;
        }

        // Check ask rules — force ask even if allowed (Edit fallback for Write)
        let ask_matched = match access.kind {
            AccessKind::Read => find_match(&self.perms.read.ask, &path).is_some(),
            AccessKind::Write => {
                find_match(&self.perms.write.ask, &path).is_some()
                    || find_match(&self.perms.edit.ask, &path).is_some()
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

        // Check allow (Edit fallback for Write)
        let allow_matched: Option<String> = match access.kind {
            AccessKind::Read => find_match(&self.perms.read.allow, &path),
            AccessKind::Write => find_match(&self.perms.write.allow, &path)
                .or_else(|| find_match(&self.perms.edit.allow, &path)),
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

/// Scan a bucket of path filters for one that covers `path`; return its rule
/// string form if found. Generic over `PathFilter` so the same helper serves
/// Read/Write/Edit buckets.
fn find_match<F: PathFilter>(bucket: &[F], path: &str) -> Option<String> {
    bucket
        .iter()
        .find(|f| f.matches(path))
        .map(|f| f.to_rule_string())
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

#[cfg(test)]
mod apply_mode_tests {
    use super::*;

    fn ask_result() -> CheckResult {
        CheckResult {
            decision: Decision::Ask,
            matched_allow: vec![],
            matched_deny: vec![],
            missing_rules: vec!["Bash(foo)".into(), "Bash(bar)".into()],
            custom_reason: None,
        }
    }

    fn allow_result() -> CheckResult {
        CheckResult {
            decision: Decision::Allow,
            matched_allow: vec!["Bash(ls *)".into()],
            matched_deny: vec![],
            missing_rules: vec![],
            custom_reason: None,
        }
    }

    fn deny_result(reason: &str) -> CheckResult {
        CheckResult {
            decision: Decision::Deny(reason.into()),
            matched_allow: vec![],
            matched_deny: vec!["Bash(rm *)".into()],
            missing_rules: vec![],
            custom_reason: None,
        }
    }

    #[test]
    fn ask_to_allow_in_bypass() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::BypassPermissions));
        assert_eq!(out.decision, Decision::Allow);
    }

    #[test]
    fn ask_to_allow_in_auto() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::Auto));
        assert_eq!(out.decision, Decision::Allow);
    }

    #[test]
    fn ask_to_deny_in_dont_ask() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::DontAsk));
        match out.decision {
            Decision::Deny(reason) => {
                assert!(
                    reason.starts_with("dontAsk mode: command requires rule(s)"),
                    "unexpected reason: {reason}",
                );
                assert!(reason.contains("Bash(foo)"));
                assert!(reason.contains("Bash(bar)"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn ask_preserved_in_default_modes() {
        for mode in [
            None,
            Some(PermissionMode::Default),
            Some(PermissionMode::Plan),
            Some(PermissionMode::AcceptEdits),
        ] {
            let out = apply_permission_mode(ask_result(), mode);
            assert_eq!(out.decision, Decision::Ask, "mode: {mode:?}");
        }
    }

    #[test]
    fn allow_preserved_in_every_mode() {
        for mode in [
            None,
            Some(PermissionMode::Default),
            Some(PermissionMode::Plan),
            Some(PermissionMode::AcceptEdits),
            Some(PermissionMode::Auto),
            Some(PermissionMode::BypassPermissions),
            Some(PermissionMode::DontAsk),
        ] {
            let out = apply_permission_mode(allow_result(), mode);
            assert_eq!(out.decision, Decision::Allow, "mode: {mode:?}");
        }
    }

    #[test]
    fn deny_preserved_in_every_mode_including_bypass() {
        for mode in [
            None,
            Some(PermissionMode::Default),
            Some(PermissionMode::Plan),
            Some(PermissionMode::AcceptEdits),
            Some(PermissionMode::Auto),
            Some(PermissionMode::BypassPermissions),
            Some(PermissionMode::DontAsk),
        ] {
            let out = apply_permission_mode(deny_result("no"), mode);
            assert!(matches!(out.decision, Decision::Deny(_)), "mode: {mode:?}");
        }
    }

    #[test]
    fn missing_rules_preserved_after_ask_to_allow_transform() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::BypassPermissions));
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(out.missing_rules, vec!["Bash(foo)", "Bash(bar)"]);
    }

    #[test]
    fn custom_reason_preserved_through_transform() {
        let mut r = ask_result();
        r.custom_reason = Some("Shell command could not be parsed".into());
        let out = apply_permission_mode(r, Some(PermissionMode::BypassPermissions));
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(
            out.custom_reason.as_deref(),
            Some("Shell command could not be parsed"),
        );
    }

    #[test]
    fn idempotent_in_bypass() {
        let once = apply_permission_mode(ask_result(), Some(PermissionMode::BypassPermissions));
        let twice = apply_permission_mode(once.clone(), Some(PermissionMode::BypassPermissions));
        assert_eq!(once, twice);
    }

    #[test]
    fn idempotent_in_dont_ask() {
        let once = apply_permission_mode(ask_result(), Some(PermissionMode::DontAsk));
        let twice = apply_permission_mode(once.clone(), Some(PermissionMode::DontAsk));
        assert_eq!(once, twice);
    }
}
