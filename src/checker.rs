use thaum::ast::*;

use crate::cmd_parser::{self, CmdParseResult};
use crate::file_access::{self, AccessKind, FileAccess};
use crate::logging;
use crate::permission::{self, ParsedPermissions};
use crate::word_util;

/// Final decision for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask(Vec<String>),
}

/// Internal result while walking the AST.
enum CheckResult {
    Ok,
    Denied(String),
}

/// Early-return on denial. Use in place of `?` for CheckResult.
macro_rules! try_check {
    ($expr:expr) => {
        match $expr {
            CheckResult::Ok => {}
            denied @ CheckResult::Denied(_) => return denied,
        }
    };
}

/// Top-level entry point: check a parsed program against permission rules.
pub fn check_program(program: &Program, perms: &ParsedPermissions, cwd: &str) -> Decision {
    let mut unmatched = Vec::new();

    for statement in &program.statements {
        if let CheckResult::Denied(reason) =
            check_expression(&statement.expression, perms, cwd, &mut unmatched)
        {
            return Decision::Deny(reason);
        }
    }

    if unmatched.is_empty() {
        Decision::Allow
    } else {
        // Deduplicate
        unmatched.sort();
        unmatched.dedup();
        Decision::Ask(unmatched)
    }
}

fn check_expression(
    expr: &Expression,
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    match expr {
        Expression::Command(cmd) => check_command(cmd, perms, cwd, unmatched),

        Expression::Pipe { left, right, .. }
        | Expression::And { left, right }
        | Expression::Or { left, right } => {
            try_check!(check_expression(left, perms, cwd, unmatched));
            check_expression(right, perms, cwd, unmatched)
        }

        Expression::Not(inner) => check_expression(inner, perms, cwd, unmatched),

        Expression::Compound { body, redirects } => {
            try_check!(check_redirects(redirects, perms, cwd, unmatched));
            check_compound(body, perms, cwd, unmatched)
        }

        Expression::FunctionDef(fndef) => {
            try_check!(check_redirects(&fndef.redirects, perms, cwd, unmatched));
            check_compound(&fndef.body, perms, cwd, unmatched)
        }
    }
}

fn check_compound(
    compound: &CompoundCommand,
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    let statement_lists: Vec<&[Statement]> = match compound {
        CompoundCommand::BraceGroup { body, .. } | CompoundCommand::Subshell { body, .. } => {
            vec![body.as_slice()]
        }
        CompoundCommand::ForClause { body, .. } => vec![body.as_slice()],
        CompoundCommand::IfClause {
            condition,
            then_body,
            elifs,
            else_body,
            ..
        } => {
            let mut lists = vec![condition.as_slice(), then_body.as_slice()];
            for elif in elifs {
                lists.push(elif.condition.as_slice());
                lists.push(elif.body.as_slice());
            }
            if let Some(eb) = else_body {
                lists.push(eb.as_slice());
            }
            lists
        }
        CompoundCommand::WhileClause {
            condition, body, ..
        }
        | CompoundCommand::UntilClause {
            condition, body, ..
        } => {
            vec![condition.as_slice(), body.as_slice()]
        }
        CompoundCommand::CaseClause { arms, .. } => {
            arms.iter().map(|a| a.body.as_slice()).collect()
        }
        CompoundCommand::BashDoubleBracket { .. }
        | CompoundCommand::BashArithmeticCommand { .. } => vec![],
        CompoundCommand::BashSelectClause { body, .. } => vec![body.as_slice()],
        CompoundCommand::BashCoproc { body, .. } => {
            return check_expression(body, perms, cwd, unmatched);
        }
        CompoundCommand::BashArithmeticFor { body, .. } => vec![body.as_slice()],
    };

    for stmts in statement_lists {
        for stmt in stmts {
            try_check!(check_expression(&stmt.expression, perms, cwd, unmatched));
        }
    }
    CheckResult::Ok
}

fn check_command(
    cmd: &Command,
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    // Assignment-only command (no command name)
    if cmd.arguments.is_empty() {
        return CheckResult::Ok;
    }

    // Extract argument literals
    let arg_literals: Vec<Option<String>> = cmd
        .arguments
        .iter()
        .map(|a| word_util::try_argument_literal(a))
        .collect();

    // Get command name
    let cmd_name = match &arg_literals[0] {
        Some(name) => name.clone(),
        None => {
            // Dynamic command name — can't determine identity
            unmatched.push("Bash(<dynamic command>)".to_string());
            // Still check redirects and process substitutions
            try_check!(check_redirects(&cmd.redirects, perms, cwd, unmatched));
            try_check!(check_argument_atoms(&cmd.arguments, perms, cwd, unmatched));
            return CheckResult::Ok;
        }
    };

    // eval — always ask
    if cmd_name == "eval" {
        unmatched.push("Bash(eval ...) -- cannot statically analyze eval".to_string());
        return CheckResult::Ok;
    }

    // Build token list for Bash() rule matching — only static tokens
    let cmd_tokens: Vec<String> = arg_literals
        .iter()
        .take_while(|a| a.is_some())
        .map(|a| a.clone().unwrap())
        .collect();

    // Check against Bash() deny rules first
    for rule in &perms.deny_bash {
        if permission::bash_rule_matches(rule, &cmd_tokens) {
            return CheckResult::Denied(format!(
                "Command '{}' matched deny rule",
                cmd_tokens.join(" ")
            ));
        }
    }

    // Check against Bash() allow rules
    let bash_allowed = perms
        .allow_bash
        .iter()
        .any(|rule| permission::bash_rule_matches(rule, &cmd_tokens));

    // Extract file accesses from redirects
    let redirect_accesses = extract_redirect_accesses(&cmd.redirects, cwd);

    // Extract file accesses from well-known command semantics (clap-based parsers)
    let cmd_parse_result = cmd_parser::parse_file_accesses(&cmd_name, &arg_literals[1..], cwd);
    let (cmd_accesses, parse_failed) = match cmd_parse_result {
        CmdParseResult::Parsed(cfa) => {
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
            (accesses, false)
        }
        CmdParseResult::ParseFailed {
            cmd_name: cn,
            message,
        } => {
            let cmd_str = cmd_tokens.join(" ");
            logging::log_parse_error(&cmd_str, &cn, &message);
            unmatched.push(format!(
                "Bash({cmd_str}) -- failed to parse arguments for `{cn}`: {message}"
            ));
            (vec![], true)
        }
    };

    // Check all file accesses
    for access in redirect_accesses.iter().chain(cmd_accesses.iter()) {
        try_check!(check_file_access(access, perms, unmatched));
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
            unmatched.push(format!("Bash({})", cmd_tokens.join(" ")));
        }
    }

    // Check process substitutions in arguments
    try_check!(check_argument_atoms(&cmd.arguments, perms, cwd, unmatched));

    // Check command substitutions in argument fragments
    try_check!(check_argument_command_subs(
        &cmd.arguments,
        perms,
        cwd,
        unmatched
    ));

    CheckResult::Ok
}

/// Check file access against Read/Write/Edit rules.
fn check_file_access(
    access: &FileAccess,
    perms: &ParsedPermissions,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    // Check deny first
    let denied = match access.kind {
        AccessKind::Read => perms
            .deny_read
            .iter()
            .any(|pat| permission::file_rule_matches(pat, &access.path)),
        AccessKind::Write => {
            perms
                .deny_write
                .iter()
                .any(|pat| permission::file_rule_matches(pat, &access.path))
                || perms
                    .deny_edit
                    .iter()
                    .any(|pat| permission::file_rule_matches(pat, &access.path))
        }
    };
    if denied {
        return CheckResult::Denied(format!(
            "File access '{}' ({:?}) matched deny rule",
            access.path, access.kind
        ));
    }

    // Check allow
    let allowed = match access.kind {
        AccessKind::Read => perms
            .allow_read
            .iter()
            .any(|pat| permission::file_rule_matches(pat, &access.path)),
        AccessKind::Write => {
            perms
                .allow_write
                .iter()
                .any(|pat| permission::file_rule_matches(pat, &access.path))
                || perms
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
        unmatched.push(rule_needed);
    }

    CheckResult::Ok
}

/// Check redirects for file access.
fn check_redirects(
    redirects: &[Redirect],
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    let accesses = extract_redirect_accesses(redirects, cwd);
    for access in &accesses {
        try_check!(check_file_access(access, perms, unmatched));
    }
    CheckResult::Ok
}

/// Extract file accesses from redirects.
fn extract_redirect_accesses(redirects: &[Redirect], cwd: &str) -> Vec<FileAccess> {
    let mut accesses = Vec::new();

    for redirect in redirects {
        let (word, kind) = match &redirect.kind {
            RedirectKind::Input(w) => (Some(w), AccessKind::Read),
            RedirectKind::Output(w) | RedirectKind::Clobber(w) => (Some(w), AccessKind::Write),
            RedirectKind::Append(w) => (Some(w), AccessKind::Write),
            RedirectKind::ReadWrite(w) => (Some(w), AccessKind::Write),
            RedirectKind::BashOutputAll(w) | RedirectKind::BashAppendAll(w) => {
                (Some(w), AccessKind::Write)
            }
            RedirectKind::HereDoc { .. } | RedirectKind::BashHereString(_) => continue,
            RedirectKind::DupInput(_) | RedirectKind::DupOutput(_) => continue,
        };

        if let Some(word) = word {
            if let Some(path) = word_util::try_literal(word) {
                // Skip /dev/* special files
                if !path.starts_with("/dev/") {
                    accesses.push(FileAccess {
                        path: file_access::resolve_path(&path, cwd),
                        kind,
                    });
                }
            }
            // Dynamic path — skip file check (command rule still gates it)
        }
    }

    accesses
}

/// Walk process substitutions in arguments.
fn check_argument_atoms(
    arguments: &[Argument],
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    for arg in arguments {
        if let Argument::Atom(Atom::BashProcessSubstitution { body, .. }) = arg {
            for stmt in body {
                try_check!(check_expression(&stmt.expression, perms, cwd, unmatched));
            }
        }
    }
    CheckResult::Ok
}

/// Walk command substitutions embedded in argument fragments.
fn check_argument_command_subs(
    arguments: &[Argument],
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    for arg in arguments {
        if let Argument::Word(word) = arg {
            try_check!(check_word_command_subs(word, perms, cwd, unmatched));
        }
    }
    CheckResult::Ok
}

fn check_word_command_subs(
    word: &Word,
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    for fragment in &word.parts {
        try_check!(check_fragment_command_subs(fragment, perms, cwd, unmatched));
    }
    CheckResult::Ok
}

fn check_fragment_command_subs(
    fragment: &Fragment,
    perms: &ParsedPermissions,
    cwd: &str,
    unmatched: &mut Vec<String>,
) -> CheckResult {
    match fragment {
        Fragment::CommandSubstitution(stmts) => {
            for stmt in stmts {
                try_check!(check_expression(&stmt.expression, perms, cwd, unmatched));
            }
        }
        Fragment::DoubleQuoted(inner) => {
            for f in inner {
                try_check!(check_fragment_command_subs(f, perms, cwd, unmatched));
            }
        }
        _ => {}
    }
    CheckResult::Ok
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
}
