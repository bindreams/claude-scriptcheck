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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Permissions;

    fn make_perms(allow: &[&str], deny: &[&str]) -> ParsedPermissions {
        permission::parse_rules(&Permissions {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        })
    }

    fn check(cmd: &str, allow: &[&str], deny: &[&str]) -> Decision {
        let perms = make_perms(allow, deny);
        let program = thaum::parse_with(cmd, thaum::Dialect::Bash).unwrap();
        check_program(&program, &perms, "/tmp")
    }

    #[test]
    fn simple_allowed_command() {
        let d = check("ls -la", &["Bash(ls *)", "Bash(ls)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn simple_unmatched_command() {
        let d = check("rm -rf /", &["Bash(ls *)"], &[]);
        assert!(matches!(d, Decision::Ask(_)));
    }

    #[test]
    fn denied_command() {
        let d = check("rm -rf /", &[], &["Bash(rm *)"]);
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn pipeline_both_allowed() {
        let d = check(
            "cat file.txt | grep foo",
            &["Bash(cat *)", "Bash(grep *)"],
            &[],
        );
        // cat reads file.txt -> needs Read rule too
        assert!(matches!(d, Decision::Ask(_)));
    }

    #[test]
    fn pipeline_both_allowed_with_read_rule() {
        let d = check(
            "cat file.txt | grep foo",
            &["Bash(cat *)", "Bash(grep *)", "Read(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn redirect_write_allowed() {
        let d = check(
            "echo hello > /tmp/claude/out.txt",
            &["Bash(echo *)", "Write(/tmp/claude/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn redirect_write_no_rule() {
        let d = check("echo hello > /etc/passwd", &["Bash(echo *)"], &[]);
        assert!(matches!(d, Decision::Ask(_)));
        if let Decision::Ask(missing) = d {
            assert!(missing.iter().any(|r| r.contains("Write(")));
        }
    }

    #[test]
    fn eval_always_asks() {
        let d = check("eval echo hello", &["Bash(eval *)", "Bash(echo *)"], &[]);
        assert!(matches!(d, Decision::Ask(_)));
    }

    #[test]
    fn empty_command_allows() {
        let d = check("FOO=bar", &[], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn and_chain() {
        let d = check(
            "echo a && echo b",
            &["Bash(echo *)", "Bash(echo)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn and_chain_partial_deny() {
        let d = check("echo a && rm foo", &["Bash(echo *)"], &["Bash(rm *)"]);
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn redirect_to_dev_null_ignored() {
        let d = check("echo hello 2>/dev/null", &["Bash(echo *)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn compound_if() {
        let d = check(
            "if true; then echo ok; fi",
            &["Bash(true)", "Bash(echo *)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn compound_for() {
        let d = check(
            "for f in a b; do echo $f; done",
            &["Bash(echo *)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn source_reads_file() {
        let d = check("source /tmp/script.sh", &["Bash(source *)"], &[]);
        assert!(matches!(d, Decision::Ask(_)));
        if let Decision::Ask(missing) = d {
            assert!(missing.iter().any(|r| r.contains("Read(")));
        }
    }

    #[test]
    fn source_reads_file_with_read_rule() {
        let d = check(
            "source /tmp/script.sh",
            &["Bash(source *)", "Read(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn append_redirect() {
        let d = check(
            "echo hello >> /tmp/claude/log.txt",
            &["Bash(echo *)", "Write(/tmp/claude/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn input_redirect() {
        let d = check(
            "wc -l < /tmp/data.txt",
            &["Bash(wc *)", "Read(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn heredoc_no_file_access() {
        let d = check(
            "cat <<EOF\nhello\nEOF\n",
            &["Bash(cat *)", "Bash(cat)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn cp_read_and_write() {
        let d = check(
            "cp /tmp/a.txt /tmp/b.txt",
            &["Bash(cp *)", "Read(/tmp/**)", "Write(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn cp_missing_write_rule() {
        let d = check(
            "cp /tmp/a.txt /home/user/b.txt",
            &["Bash(cp *)", "Read(/tmp/**)"],
            &[],
        );
        assert!(matches!(d, Decision::Ask(_)));
        if let Decision::Ask(missing) = d {
            assert!(missing.iter().any(|r| r.contains("Write(")));
        }
    }

    #[test]
    fn deny_takes_precedence_for_file() {
        let d = check(
            "cat /etc/shadow",
            &["Bash(cat *)", "Read(/etc/**)"],
            &["Read(/etc/shadow)"],
        );
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn or_chain() {
        let d = check(
            "true || echo fallback",
            &["Bash(true)", "Bash(echo *)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn negation() {
        let d = check("! true", &["Bash(true)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn dynamic_command_name() {
        let d = check("$CMD arg", &[], &[]);
        assert!(matches!(d, Decision::Ask(_)));
    }

    #[test]
    fn awk_pattern_not_treated_as_file() {
        let d = check("awk '/pattern/{ print }'", &["Bash(awk *)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn awk_double_quoted_pattern_not_treated_as_file() {
        let d = check(r#"awk "/pattern/{ print }""#, &["Bash(awk *)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn awk_with_file_reads_file_not_pattern() {
        let d = check(
            "awk '/p/' /tmp/data.txt",
            &["Bash(awk *)", "Read(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn grep_pattern_not_treated_as_file() {
        let d = check("grep 'pattern'", &["Bash(grep *)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn tr_no_file_access() {
        let d = check("tr 'a-z' 'A-Z'", &["Bash(tr *)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn sed_script_not_treated_as_file() {
        let d = check(
            "sed 's/foo/bar/' /tmp/f.txt",
            &["Bash(sed *)", "Read(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    // ---- File-only command tests ----

    #[test]
    fn mkdir_allowed_by_write_rule() {
        let d = check("mkdir /tmp/claude/foo", &["Write(/tmp/claude/**)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn mkdir_p_allowed_by_write_rule() {
        let d = check(
            "mkdir -p /tmp/claude/foo/bar",
            &["Write(/tmp/claude/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn mkdir_missing_write_rule_asks_for_write_not_bash() {
        let d = check("mkdir /home/user/foo", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(rules.iter().any(|r| r.contains("Write(")));
            assert!(!rules.iter().any(|r| r.starts_with("Bash(")));
        } else {
            panic!("expected Ask, got {:?}", d);
        }
    }

    #[test]
    fn mkdir_dynamic_arg_needs_bash_rule() {
        let d = check("mkdir $VAR", &["Write(/tmp/**)"], &[]);
        assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
    }

    #[test]
    fn mkdir_no_args_needs_bash_rule() {
        let d = check("mkdir", &["Write(/tmp/**)"], &[]);
        assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
    }

    #[test]
    fn touch_allowed_by_write_rule() {
        let d = check("touch /tmp/claude/foo", &["Write(/tmp/claude/**)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn cat_allowed_by_read_rule() {
        let d = check("cat /tmp/file.txt", &["Read(/tmp/**)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn rm_allowed_by_write_rule() {
        let d = check("rm /tmp/claude/foo.txt", &["Write(/tmp/claude/**)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn source_still_needs_bash_rule() {
        let d = check("source /tmp/script.sh", &["Read(/tmp/**)"], &[]);
        assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
    }

    #[test]
    fn cp_allowed_by_file_rules() {
        let d = check(
            "cp /tmp/a.txt /tmp/b.txt",
            &["Read(/tmp/**)", "Write(/tmp/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn cp_missing_write_asks_for_write_not_bash() {
        let d = check("cp /tmp/a.txt /home/user/b.txt", &["Read(/tmp/**)"], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(rules.iter().any(|r| r.contains("Write(")));
            assert!(!rules.iter().any(|r| r.starts_with("Bash(")));
        } else {
            panic!("expected Ask, got {:?}", d);
        }
    }

    #[test]
    fn grep_with_file_allowed_by_read_rule() {
        let d = check("grep pattern /tmp/data.txt", &["Read(/tmp/**)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn grep_stdin_only_needs_bash_rule() {
        let d = check("grep pattern", &["Read(/tmp/**)"], &[]);
        assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
    }

    #[test]
    fn file_only_with_bash_deny_still_denied() {
        let d = check(
            "mkdir /tmp/claude/foo",
            &["Write(/tmp/claude/**)"],
            &["Bash(mkdir *)"],
        );
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn file_only_with_explicit_bash_rule_still_works() {
        let d = check(
            "mkdir /tmp/claude/foo",
            &["Bash(mkdir *)", "Write(/tmp/claude/**)"],
            &[],
        );
        assert_eq!(d, Decision::Allow);
    }

    // ── Script-runner inline-script sanitization ──

    #[test]
    fn bash_c_logs_wildcard_rule() {
        let d = check("bash -c 'echo hello'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(bash -c *)"),
                "expected 'Bash(bash -c *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn bash_xc_logs_wildcard_rule() {
        let d = check("bash -xc 'echo hello'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(bash -xc *)"),
                "expected 'Bash(bash -xc *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn python_c_logs_wildcard_rule() {
        let d = check("python3 -c 'print(1)'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(python3 -c *)"),
                "expected 'Bash(python3 -c *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn python_script_file_logs_normal_rule() {
        let d = check("python3 script.py", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(python3 script.py)" || r == "Read(/tmp/script.py)"),
                "expected normal rule tokens, got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn bash_c_allowed_by_wildcard() {
        let d = check("bash -c 'echo hello'", &["Bash(bash *)"], &[]);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn ruby_e_logs_wildcard_rule() {
        let d = check("ruby -e 'puts 1'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(ruby -e *)"),
                "expected 'Bash(ruby -e *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn node_e_logs_wildcard_rule() {
        let d = check("node -e 'console.log(1)'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(node -e *)"),
                "expected 'Bash(node -e *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn perl_e_logs_wildcard_rule() {
        let d = check("perl -e 'print 1'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(perl -e *)"),
                "expected 'Bash(perl -e *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn sh_c_logs_wildcard_rule() {
        let d = check("sh -c 'ls -la'", &[], &[]);
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r == "Bash(sh -c *)"),
                "expected 'Bash(sh -c *)', got {rules:?}",
            );
        } else {
            panic!("expected Ask, got {d:?}");
        }
    }

    #[test]
    fn bash_script_file_reads() {
        let d = check("bash script.sh", &["Bash(bash *)"], &[]);
        // bash script.sh → Read(script.sh) needed
        if let Decision::Ask(ref rules) = d {
            assert!(
                rules.iter().any(|r| r.starts_with("Read(")),
                "expected Read rule, got {rules:?}",
            );
        } else {
            panic!("expected Ask for Read rule, got {d:?}");
        }
    }

    #[test]
    fn bash_script_file_with_read_rule() {
        let d = check("bash script.sh", &["Bash(bash *)", "Read(/tmp/**)"], &[]);
        assert_eq!(d, Decision::Allow);
    }
}
