use claude_scriptcheck::checker::{check_file_accesses, check_program, CheckResult, Decision};
use claude_scriptcheck::file_access::{AccessKind, FileAccess};
use claude_scriptcheck::path_util;
use claude_scriptcheck::permission::{self, ParsedPermissions};
use claude_scriptcheck::settings::Permissions;
use pretty_assertions::assert_eq;

fn make_perms_full(allow: &[&str], deny: &[&str], ask: &[&str]) -> ParsedPermissions {
    permission::parse_rules(&Permissions {
        allow: allow.iter().map(|s| s.to_string()).collect(),
        deny: deny.iter().map(|s| s.to_string()).collect(),
        ask: ask.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
}

fn make_perms(allow: &[&str], deny: &[&str]) -> ParsedPermissions {
    make_perms_full(allow, deny, &[])
}

fn check(cmd: &str, allow: &[&str], deny: &[&str]) -> CheckResult {
    let perms = make_perms(allow, deny);
    let program = thaum::parse_with(cmd, thaum::Dialect::Bash).unwrap();
    check_program(&program, &perms, "/tmp")
}

fn check_with_ask(cmd: &str, allow: &[&str], deny: &[&str], ask: &[&str]) -> CheckResult {
    let perms = make_perms_full(allow, deny, ask);
    let program = thaum::parse_with(cmd, thaum::Dialect::Bash).unwrap();
    check_program(&program, &perms, "/tmp")
}

fn check_cwd(cmd: &str, allow: &[&str], deny: &[&str], cwd: &str) -> CheckResult {
    let perms = make_perms(allow, deny);
    let program = thaum::parse_with(cmd, thaum::Dialect::Bash).unwrap();
    check_program(&program, &perms, cwd)
}

#[skuld::test]
fn simple_allowed_command() {
    let d = check("ls -la", &["Bash(ls *)", "Bash(ls)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn simple_unmatched_command() {
    let d = check("rm -rf /", &["Bash(ls *)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn denied_command() {
    let d = check("rm -rf /", &[], &["Bash(rm *)"]);
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn pipeline_both_bash_allowed_suppresses_file_rules() {
    // Both `cat` and `grep` have Bash allow rules → parser-emitted Read(file.txt)
    // requirement is suppressed. Matches the "Bash allow respects user trust" principle.
    let d = check(
        "cat file.txt | grep foo",
        &["Bash(cat *)", "Bash(grep *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn pipeline_both_allowed_with_read_rule() {
    let d = check(
        "cat file.txt | grep foo",
        &["Bash(cat *)", "Bash(grep *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn redirect_write_allowed() {
    let d = check(
        "echo hello > /tmp/claude/out.txt",
        &["Bash(echo *)", "Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn redirect_write_allowed_by_bash_rule_alone() {
    // Bash(echo *) allow suppresses the redirect-emitted Write(/etc/passwd)
    // requirement. A Deny(Write(/etc/**)) would still fire — see
    // redirect_write_deny_still_fires_under_bash_allow.
    let d = check("echo hello > /etc/passwd", &["Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn eval_allowed_by_bash_eval_rule() {
    // Bash(eval *) explicitly accepts eval's dynamic nature. Suppression applies.
    let d = check("eval echo hello", &["Bash(eval *)", "Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn empty_command_allows() {
    let d = check("FOO=bar", &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn and_chain() {
    let d = check("echo a && echo b", &["Bash(echo *)", "Bash(echo)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn and_chain_partial_deny() {
    let d = check("echo a && rm foo", &["Bash(echo *)"], &["Bash(rm *)"]);
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn redirect_to_dev_null_allowed_by_bash_rule_alone() {
    let d = check("echo hello 2>/dev/null", &["Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);

    let d = check(
        "echo hello 2>/dev/null",
        &["Bash(echo *)", "Write(/dev/*)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn redirect_to_dev_null_no_bash_rule_asks_for_write() {
    // Without Bash allow, the redirect still drives a Write rule requirement.
    let d = check("echo hello 2>/dev/null", &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.contains("Write(")));
}

#[skuld::test]
fn compound_if() {
    let d = check(
        "if true; then echo ok; fi",
        &["Bash(true)", "Bash(echo *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn compound_for() {
    let d = check("for f in a b; do echo $f; done", &["Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn source_allowed_by_bash_rule_alone() {
    // Bash(source *) suppresses the parser-emitted Read(/tmp/script.sh) requirement.
    let d = check("source /tmp/script.sh", &["Bash(source *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn source_without_bash_rule_asks_for_read() {
    let d = check("source /tmp/script.sh", &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.contains("Read(")));
}

#[skuld::test]
fn source_reads_file_with_read_rule() {
    let d = check(
        "source /tmp/script.sh",
        &["Bash(source *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn append_redirect() {
    let d = check(
        "echo hello >> /tmp/claude/log.txt",
        &["Bash(echo *)", "Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn input_redirect() {
    let d = check(
        "wc -l < /tmp/data.txt",
        &["Bash(wc *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn heredoc_no_file_access() {
    let d = check(
        "cat <<EOF\nhello\nEOF\n",
        &["Bash(cat *)", "Bash(cat)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn cp_read_and_write() {
    let d = check(
        "cp /tmp/a.txt /tmp/b.txt",
        &["Bash(cp *)", "Read(/tmp/**)", "Write(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn cp_bash_allow_suppresses_write_requirement() {
    // Bash(cp *) allow suppresses the parser-emitted Write(/home/user/b.txt)
    // requirement. Deny(Write(/home/**)) would still fire.
    let d = check(
        "cp /tmp/a.txt /home/user/b.txt",
        &["Bash(cp *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn cp_without_bash_rule_asks_for_missing_write() {
    let d = check(
        "cp /tmp/a.txt /home/user/b.txt",
        &["Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.contains("Write(")));
}

#[skuld::test]
fn deny_takes_precedence_for_file() {
    let d = check(
        "cat /etc/shadow",
        &["Bash(cat *)", "Read(/etc/**)"],
        &["Read(/etc/shadow)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn or_chain() {
    let d = check(
        "true || echo fallback",
        &["Bash(true)", "Bash(echo *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn negation() {
    let d = check("! true", &["Bash(true)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn dynamic_command_name() {
    let d = check("$CMD arg", &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn awk_pattern_not_treated_as_file() {
    let d = check("awk '/pattern/{ print }'", &["Bash(awk *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn awk_double_quoted_pattern_not_treated_as_file() {
    let d = check(r#"awk "/pattern/{ print }""#, &["Bash(awk *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn awk_with_file_reads_file_not_pattern() {
    let d = check(
        "awk '/p/' /tmp/data.txt",
        &["Bash(awk *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn grep_pattern_not_treated_as_file() {
    let d = check("grep 'pattern'", &["Bash(grep *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn tr_no_file_access() {
    let d = check("tr 'a-z' 'A-Z'", &["Bash(tr *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn sed_script_not_treated_as_file() {
    let d = check(
        "sed 's/foo/bar/' /tmp/f.txt",
        &["Bash(sed *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

// ── File-only command tests ─────────────────────────────────────────────────

#[skuld::test]
fn mkdir_allowed_by_write_rule() {
    let d = check("mkdir /tmp/claude/foo", &["Write(/tmp/claude/**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn mkdir_p_allowed_by_write_rule() {
    let d = check(
        "mkdir -p /tmp/claude/foo/bar",
        &["Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn mkdir_missing_write_rule_asks_for_write_not_bash() {
    let d = check("mkdir /home/user/foo", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(rules.iter().any(|r| r.contains("Write(")));
        assert!(!rules.iter().any(|r| r.starts_with("Bash(")));
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn mkdir_dynamic_arg_needs_bash_rule() {
    let d = check("mkdir $VAR", &["Write(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.starts_with("Bash(")));
}

#[skuld::test]
fn mkdir_no_args_needs_bash_rule() {
    let d = check("mkdir", &["Write(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.starts_with("Bash(")));
}

#[skuld::test]
fn touch_allowed_by_write_rule() {
    let d = check("touch /tmp/claude/foo", &["Write(/tmp/claude/**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn cat_allowed_by_read_rule() {
    let d = check("cat /tmp/file.txt", &["Read(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rm_allowed_by_write_rule() {
    let d = check("rm /tmp/claude/foo.txt", &["Write(/tmp/claude/**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn source_still_needs_bash_rule() {
    let d = check("source /tmp/script.sh", &["Read(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.starts_with("Bash(")));
}

#[skuld::test]
fn cp_allowed_by_file_rules() {
    let d = check(
        "cp /tmp/a.txt /tmp/b.txt",
        &["Read(/tmp/**)", "Write(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn cp_missing_write_asks_for_write_not_bash() {
    let d = check("cp /tmp/a.txt /home/user/b.txt", &["Read(/tmp/**)"], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(rules.iter().any(|r| r.contains("Write(")));
        assert!(!rules.iter().any(|r| r.starts_with("Bash(")));
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn grep_with_file_allowed_by_read_rule() {
    let d = check("grep pattern /tmp/data.txt", &["Read(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn grep_stdin_only_needs_bash_rule() {
    let d = check("grep pattern", &["Read(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(d.missing_rules.iter().any(|r| r.starts_with("Bash(")));
}

#[skuld::test]
fn file_only_with_bash_deny_still_denied() {
    let d = check(
        "mkdir /tmp/claude/foo",
        &["Write(/tmp/claude/**)"],
        &["Bash(mkdir *)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn file_only_with_explicit_bash_rule_still_works() {
    let d = check(
        "mkdir /tmp/claude/foo",
        &["Bash(mkdir *)", "Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn file_only_with_bash_ask_still_asks() {
    let d = check_with_ask(
        "mkdir /tmp/claude/foo",
        &["Write(/tmp/claude/**)"],
        &[],
        &["Bash(mkdir *)"],
    );
    assert_eq!(d.decision, Decision::Ask);
}

// ── Bare rules (tool-level wildcards) ──

#[skuld::test]
fn bare_read_allows_file_access() {
    let d = check("cat /tmp/file.txt", &["Bash(cat *)", "Read"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bare_write_allows_file_access() {
    let d = check("echo hi > /tmp/out.txt", &["Bash(echo *)", "Write"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

// ── Script-runner inline-script sanitization ──

#[skuld::test]
fn bash_c_logs_wildcard_rule() {
    let d = check("bash -c 'echo hello'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(bash -c *)"),
            "expected 'Bash(bash -c *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn bash_xc_logs_wildcard_rule() {
    let d = check("bash -xc 'echo hello'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(bash -xc *)"),
            "expected 'Bash(bash -xc *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn python_c_pure_computation_allows() {
    // Python AST analysis sees print(1) has no file I/O → auto-allow
    let d = check("python3 -c 'print(1)'", &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_c_unanalyzable_logs_wildcard_rule() {
    // exec() is unanalyzable → falls back to Bash(python3 -c *)
    let d = check("python3 -c 'exec(\"bad\")'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(python3 -c *)"),
            "expected 'Bash(python3 -c *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn python_script_file_logs_normal_rule() {
    let d = check("python3 script.py", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules
                .iter()
                .any(|r| r == "Bash(python3 script.py)" || r == "Read(/tmp/script.py)"),
            "expected normal rule tokens, got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn bash_c_allowed_by_wildcard() {
    let d = check("bash -c 'echo hello'", &["Bash(bash *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn ruby_e_logs_wildcard_rule() {
    let d = check("ruby -e 'puts 1'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(ruby -e *)"),
            "expected 'Bash(ruby -e *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn node_e_logs_wildcard_rule() {
    let d = check("node -e 'console.log(1)'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(node -e *)"),
            "expected 'Bash(node -e *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn perl_e_logs_wildcard_rule() {
    let d = check("perl -e 'print 1'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(perl -e *)"),
            "expected 'Bash(perl -e *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn sh_c_logs_wildcard_rule() {
    let d = check("sh -c 'ls -la'", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(sh -c *)"),
            "expected 'Bash(sh -c *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn bash_script_file_reads_allowed_by_bash_rule_alone() {
    let d = check("bash script.sh", &["Bash(bash *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bash_script_file_reads_without_bash_rule_asks_for_read() {
    let d = check("bash script.sh", &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Read(")),
        "expected Read rule, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn bash_script_file_with_read_rule() {
    let d = check("bash script.sh", &["Bash(bash *)", "Read(/tmp/**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

// ── Ask rule semantics ──────────────────────────────────────────────────────

#[skuld::test]
fn ask_rule_overrides_allow_bash() {
    let d = check_with_ask("ls -la", &["Bash(ls *)"], &[], &["Bash(ls *)"]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn ask_rule_does_not_override_deny() {
    let d = check_with_ask("rm -rf /tmp/foo", &[], &["Bash(rm *)"], &["Bash(rm *)"]);
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn bash_allow_overrides_file_read_ask() {
    // Design decision: a matching Bash(...) allow rule suppresses file Ask rules.
    // Users who explicitly allowed the command at the Bash level are not re-prompted
    // for its file accesses, matching the consistent "Bash allow = trust" principle.
    let d = check_with_ask(
        "cat /tmp/secret.txt",
        &["Bash(cat *)", "Read(/tmp/**)"],
        &[],
        &["Read(/tmp/secret.txt)"],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bash_allow_overrides_file_write_ask() {
    let d = check_with_ask(
        "echo hello > /tmp/out.txt",
        &["Bash(echo *)", "Write(/tmp/**)"],
        &[],
        &["Write(/tmp/out.txt)"],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn file_ask_still_fires_without_bash_allow() {
    // Without Bash allow, file Ask rules still force Ask (existing behavior).
    let d = check_with_ask(
        "cat /tmp/secret.txt",
        &["Read(/tmp/**)"],
        &[],
        &["Read(/tmp/secret.txt)"],
    );
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn ask_rule_no_match_allows_through() {
    let d = check_with_ask("ls -la", &["Bash(ls *)"], &[], &["Bash(rm *)"]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn empty_ask_rules_unchanged_behavior() {
    let d = check_with_ask("ls -la", &["Bash(ls *)"], &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

// ── Path canonicalization ────────────────────────────────────────────────────

/// Helper: returns the canonical form of a path (best-effort).
fn c(path: &str) -> String {
    claude_scriptcheck::canonicalize::best_effort_canonicalize(path)
}

#[skuld::test]
fn dotdot_query_path_matches_clean_rule() {
    // Use a real temp dir as CWD so relative paths resolve correctly on all platforms.
    // Canonicalize to resolve 8.3 short names on Windows.
    let tmp = path_util::normalize_separators(
        &std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .to_string_lossy(),
    );
    let rule = format!("Read({tmp}/**)");
    let d = check_cwd(
        "cat ../file.txt",
        &[&rule, "Bash(cat *)"],
        &[],
        &format!("{tmp}/subdir"),
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_with_dotdot_matches_normalized_query() {
    let d = check(
        "cat /tmp/file.txt",
        &[
            &format!("Read({}/nonexistent/../**)", c("/tmp")),
            "Bash(cat *)",
        ],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn dot_in_query_path_resolved() {
    let d = check(
        "cat ./file.txt",
        &[&format!("Read({}/**)", c("/tmp")), "Bash(cat *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn relative_path_in_query_canonicalized() {
    let d = check(
        "mkdir subdir/foo",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

// ── check_file_accesses tests ────────────────────────────────────────────────

fn check_accesses(accesses: &[FileAccess], allow: &[&str], deny: &[&str]) -> CheckResult {
    let perms = make_perms(allow, deny);
    check_file_accesses(accesses, &perms, "/tmp")
}

fn check_accesses_full(
    accesses: &[FileAccess],
    allow: &[&str],
    deny: &[&str],
    ask: &[&str],
) -> CheckResult {
    let perms = make_perms_full(allow, deny, ask);
    check_file_accesses(accesses, &perms, "/tmp")
}

#[skuld::test]
fn file_accesses_read_allowed() {
    let accesses = [FileAccess {
        path: "/tmp/data.txt".into(),
        kind: AccessKind::Read,
    }];
    let result = check_file_accesses(&accesses, &make_perms(&["Read(/tmp/**)"], &[]), "/tmp");
    assert_eq!(result.decision, Decision::Allow);
    assert!(
        result.matched_allow.iter().any(|r| r.contains("Read(")),
        "expected matched_allow to contain Read rule, got {:?}",
        result.matched_allow,
    );
}

#[skuld::test]
fn file_accesses_read_denied() {
    let accesses = [FileAccess {
        path: "/etc/shadow".into(),
        kind: AccessKind::Read,
    }];
    let result = check_file_accesses(
        &accesses,
        &make_perms(&["Read(/etc/**)"], &["Read(/etc/shadow)"]),
        "/tmp",
    );
    assert!(matches!(result.decision, Decision::Deny(_)));
    assert!(
        result.matched_deny.iter().any(|r| r.contains("Read(")),
        "expected matched_deny to contain Read rule, got {:?}",
        result.matched_deny,
    );
}

#[skuld::test]
fn file_accesses_read_no_matching_rule_asks() {
    let d = check_accesses(
        &[FileAccess {
            path: "/home/user/secret.txt".into(),
            kind: AccessKind::Read,
        }],
        &[],
        &[],
    );
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r.contains("Read(")),
            "expected Ask with Read rule, got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn file_accesses_read_ask_overrides_allow() {
    let d = check_accesses_full(
        &[FileAccess {
            path: "/tmp/secret.txt".into(),
            kind: AccessKind::Read,
        }],
        &["Read(/tmp/**)"],
        &[],
        &["Read(/tmp/secret.txt)"],
    );
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn file_accesses_write_allowed() {
    let d = check_accesses(
        &[FileAccess {
            path: "/tmp/out.txt".into(),
            kind: AccessKind::Write,
        }],
        &["Write(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn file_accesses_write_allowed_by_edit_fallback() {
    let d = check_accesses(
        &[FileAccess {
            path: "/tmp/out.txt".into(),
            kind: AccessKind::Write,
        }],
        &["Edit(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn file_accesses_write_denied() {
    let d = check_accesses(
        &[FileAccess {
            path: "/etc/passwd".into(),
            kind: AccessKind::Write,
        }],
        &[],
        &["Write(/etc/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn file_accesses_empty_list_allows() {
    let d = check_accesses(&[], &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn file_accesses_multiple_with_deny_stops_early() {
    let accesses = [
        FileAccess {
            path: "/etc/shadow".into(),
            kind: AccessKind::Read,
        },
        FileAccess {
            path: "/tmp/safe.txt".into(),
            kind: AccessKind::Read,
        },
    ];
    let d = check_accesses(&accesses, &["Read(/tmp/**)"], &["Read(/etc/shadow)"]);
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn file_accesses_multiple_unmatched_collected() {
    let accesses = [
        FileAccess {
            path: "/home/a.txt".into(),
            kind: AccessKind::Read,
        },
        FileAccess {
            path: "/home/b.txt".into(),
            kind: AccessKind::Read,
        },
    ];
    let d = check_accesses(&accesses, &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.len() >= 2,
            "expected at least 2 unmatched rules, got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn file_accesses_write_denied_by_edit_rule() {
    let d = check_accesses(
        &[FileAccess {
            path: "/etc/config.json".into(),
            kind: AccessKind::Write,
        }],
        &[],
        &["Edit(/etc/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

// Python AST analysis integration tests =====

#[skuld::test]
fn python_c_open_read_with_read_rule_allows() {
    let d = check(
        r#"python3 -c "open('/tmp/x').read()""#,
        &["Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_c_open_write_with_write_rule_allows() {
    let d = check(
        r#"python3 -c "open('/tmp/x', 'w').write('hi')""#,
        &["Write(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_c_open_write_without_rule_asks_specific_path() {
    let d = check(r#"python3 -c "open('/tmp/x', 'w')""#, &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        // /tmp may be canonicalized to /private/tmp on macOS
        assert!(
            rules
                .iter()
                .any(|r| r.starts_with("Write(") && r.contains("/tmp/x")),
            "expected Write(.../tmp/x), got {rules:?}",
        );
        // Should NOT fall back to Bash(python3 -c *)
        assert!(
            !rules.iter().any(|r| r.starts_with("Bash(")),
            "should not ask for Bash rule when Python analysis succeeded, got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn python_c_open_write_denied_by_rule() {
    let d = check(
        r#"python3 -c "open('/tmp/x', 'w')""#,
        &[],
        &["Write(/tmp/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn python_c_import_subprocess_asks_wildcard() {
    let d = check(r#"python3 -c "import subprocess""#, &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(python3 -c *)"),
            "expected 'Bash(python3 -c *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn python_c_in_pipeline_allows() {
    let d = check(
        r#"python3 -c "open('/tmp/x').read()" && echo done"#,
        &["Read(/tmp/**)", "Bash(echo *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_not_python3_also_analyzed() {
    let d = check(
        r#"python -c "open('/tmp/x').read()""#,
        &["Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_c_bash_ask_rule_forces_ask() {
    // If there's an explicit Bash ask rule, Python analysis doesn't suppress it
    let d = check_with_ask(r#"python3 -c "print(42)""#, &[], &[], &["Bash(python3 *)"]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn python_c_bash_deny_rule_still_denies() {
    let d = check(r#"python3 -c "print(42)""#, &[], &["Bash(python3 *)"]);
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn python_c_with_open_read_allows() {
    let d = check(
        r#"python3 -c "
with open('/tmp/data.json') as f:
    data = f.read()
print(data)
""#,
        &["Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_c_json_load_open_allows() {
    let d = check(
        r#"python3 -c "import json; data = json.load(open('/tmp/data.json'))""#,
        &["Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_c_multiple_accesses_all_checked() {
    // Read is allowed but Write is not → Ask for Write
    let d = check(
        r#"python3 -c "open('/tmp/a'); open('/tmp/b', 'w')""#,
        &["Read(/tmp/**)"],
        &[],
    );
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r.starts_with("Write(")),
            "expected Write rule, got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

// Command name normalization =====

#[skuld::test]
fn python_exe_normalized_for_analysis() {
    let d = check(r#"python.exe -c "print(1)""#, &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn absolute_path_python_normalized() {
    let d = check(r#"/usr/bin/python3 -c "print(1)""#, &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn versioned_python_normalized() {
    let d = check(r#"python3.12 -c "print(1)""#, &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn deny_rule_matches_normalized_name() {
    let d = check(
        r#"/usr/bin/python3 -c "print(1)""#,
        &[],
        &["Bash(python3 *)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

// uv run wrapper =====

#[skuld::test]
fn uv_run_python_c_allows() {
    let d = check(r#"uv run python -c "import json; print(1)""#, &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn uv_run_with_flag_python_c_allows() {
    let d = check(
        r#"uv run --with requests python -c "import json; print(1)""#,
        &[],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn uv_run_python_c_unanalyzable_asks_for_bash() {
    let d = check(r#"uv run python -c "import subprocess""#, &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r == "Bash(uv run python -c *)"),
            "expected 'Bash(uv run python -c *)', got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

#[skuld::test]
fn uv_run_python_versioned_allows() {
    let d = check(r#"uv run python3.12 -c "print(1)""#, &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

// Git subcommand file-only suppression =====

#[skuld::test]
fn git_restore_allowed_by_write_rule() {
    // git restore . with Write rule covering cwd → should Allow without Bash rule
    let d = check("git restore .", &[&format!("Write({}/**)", c("/tmp"))], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_add_allowed_by_git_write_rule() {
    // git add needs Write(.git) — allowed by Write(cwd/**)
    let d = check(
        "git add file.txt",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_commit_allowed_by_git_write_rule() {
    let d = check(
        "git commit -m 'msg'",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_status_no_rules_allowed() {
    // git status is read-only and file_only=true with no accesses → no Bash rule needed
    let d = check("git status", &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_log_no_rules_allowed() {
    let d = check("git log --oneline", &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_diff_no_rules_allowed() {
    let d = check("git diff", &[], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_fetch_requires_bash_rule() {
    // fetch is file_only=false → Write rule alone is not enough
    let d = check(
        "git fetch origin",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Ask, "expected Ask, got {d:?}");
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Bash(")),
        "expected Bash rule in missing, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn git_push_requires_bash_rule() {
    let d = check(
        "git push origin main",
        &[&format!("Read({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Ask, "expected Ask, got {d:?}");
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Bash(")),
        "expected Bash rule in missing, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn git_fetch_allowed_with_bash_and_write_rules() {
    let d = check(
        "git fetch origin",
        &["Bash(git fetch *)", &format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_unknown_subcommand_requires_bash_rule() {
    // bisect is unknown → file_only=None → is_file_only_command("git")=false → needs Bash rule
    let d = check(
        "git bisect start",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Ask, "expected Ask, got {d:?}");
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Bash(")),
        "expected Bash rule in missing, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn git_c_flag_path_resolution() {
    // git -C /other restore . → writes to /other, not /tmp
    let d = check_cwd(
        "git -C /nonexistent_unique_path restore .",
        &["Write(/nonexistent_unique_path/**)"],
        &[],
        "/tmp",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_checkout_branch_needs_write() {
    // checkout writes to working tree + .git
    let d = check(
        "git checkout main",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_merge_needs_write() {
    let d = check(
        "git merge feature",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_reset_hard_needs_write() {
    let d = check(
        "git reset --hard HEAD~1",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_restore_denied() {
    let d = check("git restore .", &[], &[&format!("Write({}/**)", c("/tmp"))]);
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn git_restore_missing_write_asks_for_write() {
    let d = check("git restore .", &[], &[]);
    if d.decision == Decision::Ask {
        let rules = &d.missing_rules;
        assert!(
            rules.iter().any(|r| r.starts_with("Write(")),
            "expected Write rule, got {rules:?}",
        );
        // Should NOT ask for Bash rule (file_only=true)
        assert!(
            !rules.iter().any(|r| r.starts_with("Bash(")),
            "should not need Bash rule for file-only git subcommand, got {rules:?}",
        );
    } else {
        panic!("expected Ask, got {d:?}");
    }
}

// ── Bash allow suppresses secondary rule demands ─────────────────────────────
// When a matching Bash(...) allow rule fires, the parser-emitted, redirect-
// derived, parse-failure, eval, and dynamic-cmd-name secondary rule demands
// are suppressed. File Deny rules still fire; Ask(Bash(...)) still prevents
// suppression by forcing bash_allowed=false.

#[skuld::test]
fn git_fetch_with_bash_rule_alone_is_allow() {
    // Primary regression test for the 2026-04-23 report.
    let d = check("git fetch origin", &["Bash(git fetch *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn git_fetch_bash_rule_does_not_bypass_write_deny() {
    let d = check(
        "git fetch origin",
        &["Bash(git fetch *)"],
        &[&format!("Write({}/**)", c("/tmp"))],
    );
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

#[skuld::test]
fn git_push_with_bash_rule_alone_is_allow() {
    let d = check("git push origin main", &["Bash(git push *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bash_allow_suppresses_file_read_ask_with_matched_allow_logged() {
    let d = check_with_ask(
        "cat /tmp/x",
        &["Bash(cat *)"],
        &[],
        &["Read(/tmp/x)"],
    );
    assert_eq!(d.decision, Decision::Allow);
    assert!(
        d.matched_allow.iter().any(|r| r == "Bash(cat *)"),
        "expected Bash(cat *) in matched_allow, got {:?}",
        d.matched_allow,
    );
}

#[skuld::test]
fn bash_ask_rule_prevents_suppression_of_write_rule_demand() {
    let d = check_with_ask(
        "git fetch origin",
        &["Bash(git fetch *)"],
        &[],
        &["Bash(git fetch *)"],
    );
    assert_eq!(d.decision, Decision::Ask);
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Write(")),
        "expected Write rule in missing, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn python_inline_script_with_bash_rule_alone_is_allow() {
    let d = check(
        r#"python3 -c "open('/tmp/x').read()""#,
        &["Bash(python3 -c *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn python_bash_ask_plus_allow_still_asks() {
    // Ask(Bash(python3 -c *)) forces bash_allowed=false, so file accesses matter.
    let d = check_with_ask(
        r#"python3 -c "open('/tmp/x').read()""#,
        &["Bash(python3 -c *)"],
        &[],
        &["Bash(python3 -c *)"],
    );
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn echo_stdout_redirect_with_bash_rule_alone_is_allow() {
    let d = check("echo x > /etc/hosts", &["Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn echo_append_redirect_suppressed() {
    let d = check("echo x >> /etc/hosts", &["Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn cat_input_redirect_suppressed() {
    let d = check("cat < /etc/hosts", &["Bash(cat *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn redirect_write_deny_still_fires_under_bash_allow() {
    let d = check(
        "echo x > /etc/hosts",
        &["Bash(echo *)"],
        &["Write(/etc/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

#[skuld::test]
fn cat_with_bash_rule_alone_is_allow() {
    let d = check("cat /tmp/x", &["Bash(cat *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

// Parse failure

#[skuld::test]
fn parse_failure_suppressed_by_bash_allow() {
    // `git worktree add <path>` with an unrecognized value-taking flag triggers
    // clap parse failure. Under Bash(git *) allow, the failure is suppressed.
    let d = check(
        "git worktree add --notaflag something",
        &["Bash(git *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn parse_failure_without_bash_allow_still_asks() {
    let d = check("git worktree add --notaflag something", &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

// Eval

#[skuld::test]
fn eval_bash_deny_fires_now() {
    // Behavior improvement: eval early-return used to mask Bash deny rules.
    // With the restructure, Deny(Bash(eval *)) now correctly fires as Deny.
    let d = check("eval $X", &[], &["Bash(eval *)"]);
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

#[skuld::test]
fn eval_without_rules_still_asks() {
    let d = check("eval $X", &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

// Dynamic command name

#[skuld::test]
fn dynamic_cmd_name_allowed_by_bash_wildcard() {
    let d = check("$CMD arg", &["Bash(*)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
    assert!(
        d.matched_allow.iter().any(|r| r == "Bash(*)"),
        "expected Bash(*) in matched_allow, got {:?}",
        d.matched_allow,
    );
}

#[skuld::test]
fn dynamic_cmd_name_allowed_by_bash_double_star() {
    let d = check("$CMD arg", &["Bash(**)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn dynamic_cmd_name_blocked_by_bash_wildcard_deny() {
    // New behavior: Deny(Bash(*)) now blocks dynamic-cmd-name invocations.
    // Previously the dynamic path short-circuited before any deny scan.
    let d = check("$CMD arg", &[], &["Bash(*)"]);
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

#[skuld::test]
fn dynamic_cmd_name_redirect_deny_fires_under_wildcard_allow() {
    let d = check(
        "$CMD arg > /etc/hosts",
        &["Bash(*)"],
        &["Write(/etc/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

#[skuld::test]
fn dynamic_cmd_name_narrow_bash_rule_does_not_match() {
    // Bash(ls *) has prefix ["ls"] — does NOT match empty tokens.
    let d = check("$CMD arg", &["Bash(ls *)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

// Nested contexts (command substitution, process substitution)

#[skuld::test]
fn command_substitution_inner_bash_allow_suppresses_inner_file_access() {
    let d = check(
        "echo $(git fetch origin)",
        &["Bash(echo *)", "Bash(git fetch *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn command_substitution_outer_allow_does_not_leak_to_inner() {
    let d = check("echo $(git fetch origin)", &["Bash(echo *)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(
        d.missing_rules
            .iter()
            .any(|r| r == "Bash(git fetch *)" || r.starts_with("Bash(git fetch")),
        "expected Bash(git fetch *) in missing, got {:?}",
        d.missing_rules,
    );
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Write(")),
        "expected Write(.git) in missing, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn process_substitution_inner_bash_allow_suppresses_inner_file_access() {
    let d = check(
        "diff <(git fetch origin) /tmp/x",
        &["Bash(diff *)", "Bash(git fetch *)", &format!("Read({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn compound_redirect_not_suppressed_by_inner_bash_allow() {
    // Inner `git fetch` suppresses its own Write(.git) via inner bash_allowed.
    // The compound-level redirect to /tmp/out runs through visit_redirect with
    // suppress=false and still requires a Write rule.
    let d = check(
        "{ git fetch origin; } > /tmp/out",
        &["Bash(git fetch *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Ask);
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Write(")),
        "expected Write rule in missing, got {:?}",
        d.missing_rules,
    );
}

// Bash(*) wildcard

#[skuld::test]
fn bash_wildcard_suppresses_file_accesses() {
    let d = check("git fetch origin", &["Bash(*)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bash_wildcard_does_not_override_file_deny() {
    let d = check(
        "git fetch origin",
        &["Bash(*)"],
        &[&format!("Write({}/**)", c("/tmp"))],
    );
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

// Security tradeoff — documented in CLAUDE.md

#[skuld::test]
fn bash_git_wildcard_allows_c_flag_injection() {
    // Documented tradeoff: Bash(git *) trusts all git, including -c config overrides
    // that register hooks, aliases, or external diff/pager/credential handlers.
    let d = check(
        "git -c core.hooksPath=/evil fetch origin",
        &["Bash(git *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bash_git_fetch_allow_does_not_cover_c_flag_injection() {
    // Narrow Bash(git fetch *) does NOT match tokens starting "git -c ... fetch ...".
    // The -c guardrail still fires for users with narrow rules.
    let d = check(
        "git -c core.hooksPath=/evil fetch origin",
        &["Bash(git fetch *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Ask);
    assert!(
        d.missing_rules.iter().any(|r| r.starts_with("Bash(")),
        "expected Bash rule in missing, got {:?}",
        d.missing_rules,
    );
}

#[skuld::test]
fn git_config_dangerous_write_under_bash_wildcard_allow() {
    // Documented tradeoff: Bash(git config *) suppresses the git-config-write guardrail.
    let d = check(
        "git config core.pager '!evil'",
        &["Bash(git config *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn herestring_no_op_for_bash_allow_suppression() {
    // Here-strings (`<<<`) emit no file access; the fix is a no-op here.
    let d = check(r#"cat <<< "hi""#, &["Bash(cat *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn parse_failure_redirect_also_suppressed_under_bash_allow() {
    // Parse failure + redirect under Bash allow: both suppressed → Allow.
    let d = check(
        "git worktree add --notaflag something > /etc/test-output.txt",
        &["Bash(git *)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn parse_failure_redirect_deny_still_fires_under_bash_allow() {
    let d = check(
        "git worktree add --notaflag something > /etc/test-output.txt",
        &["Bash(git *)"],
        &["Write(/etc/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)), "expected Deny, got {d:?}");
}

#[skuld::test]
fn dynamic_cmd_name_allowed_by_bash_double_star_space_star() {
    // `Bash(** *)` also matches empty tokens (the `**` recursive-skip loop in
    // BashFilter::matches falls through to empty-prefix + wildcard).
    let d = check("$CMD arg", &["Bash(** *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}
