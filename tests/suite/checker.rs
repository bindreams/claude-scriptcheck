use claude_scriptcheck::checker::{check_program, Decision};
use claude_scriptcheck::permission::{self, ParsedPermissions};
use claude_scriptcheck::settings::Permissions;
use pretty_assertions::assert_eq;

fn make_perms_full(allow: &[&str], deny: &[&str], ask: &[&str]) -> ParsedPermissions {
    permission::parse_rules(&Permissions {
        allow: allow.iter().map(|s| s.to_string()).collect(),
        deny: deny.iter().map(|s| s.to_string()).collect(),
        ask: ask.iter().map(|s| s.to_string()).collect(),
    })
}

fn make_perms(allow: &[&str], deny: &[&str]) -> ParsedPermissions {
    make_perms_full(allow, deny, &[])
}

fn check(cmd: &str, allow: &[&str], deny: &[&str]) -> Decision {
    let perms = make_perms(allow, deny);
    let program = thaum::parse_with(cmd, thaum::Dialect::Bash).unwrap();
    check_program(&program, &perms, "/tmp").decision
}

fn check_with_ask(cmd: &str, allow: &[&str], deny: &[&str], ask: &[&str]) -> Decision {
    let perms = make_perms_full(allow, deny, ask);
    let program = thaum::parse_with(cmd, thaum::Dialect::Bash).unwrap();
    check_program(&program, &perms, "/tmp").decision
}

#[skuld::test]
fn simple_allowed_command() {
    let d = check("ls -la", &["Bash(ls *)", "Bash(ls)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn simple_unmatched_command() {
    let d = check("rm -rf /", &["Bash(ls *)"], &[]);
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn denied_command() {
    let d = check("rm -rf /", &[], &["Bash(rm *)"]);
    assert!(matches!(d, Decision::Deny(_)));
}

#[skuld::test]
fn pipeline_both_allowed() {
    let d = check(
        "cat file.txt | grep foo",
        &["Bash(cat *)", "Bash(grep *)"],
        &[],
    );
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn pipeline_both_allowed_with_read_rule() {
    let d = check(
        "cat file.txt | grep foo",
        &["Bash(cat *)", "Bash(grep *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn redirect_write_allowed() {
    let d = check(
        "echo hello > /tmp/claude/out.txt",
        &["Bash(echo *)", "Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn redirect_write_no_rule() {
    let d = check("echo hello > /etc/passwd", &["Bash(echo *)"], &[]);
    assert!(matches!(d, Decision::Ask(_)));
    if let Decision::Ask(missing) = d {
        assert!(missing.iter().any(|r| r.contains("Write(")));
    }
}

#[skuld::test]
fn eval_always_asks() {
    let d = check("eval echo hello", &["Bash(eval *)", "Bash(echo *)"], &[]);
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn empty_command_allows() {
    let d = check("FOO=bar", &[], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn and_chain() {
    let d = check(
        "echo a && echo b",
        &["Bash(echo *)", "Bash(echo)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn and_chain_partial_deny() {
    let d = check("echo a && rm foo", &["Bash(echo *)"], &["Bash(rm *)"]);
    assert!(matches!(d, Decision::Deny(_)));
}

#[skuld::test]
fn redirect_to_dev_null_ignored() {
    let d = check("echo hello 2>/dev/null", &["Bash(echo *)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn compound_if() {
    let d = check(
        "if true; then echo ok; fi",
        &["Bash(true)", "Bash(echo *)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn compound_for() {
    let d = check(
        "for f in a b; do echo $f; done",
        &["Bash(echo *)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn source_reads_file() {
    let d = check("source /tmp/script.sh", &["Bash(source *)"], &[]);
    assert!(matches!(d, Decision::Ask(_)));
    if let Decision::Ask(missing) = d {
        assert!(missing.iter().any(|r| r.contains("Read(")));
    }
}

#[skuld::test]
fn source_reads_file_with_read_rule() {
    let d = check(
        "source /tmp/script.sh",
        &["Bash(source *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn append_redirect() {
    let d = check(
        "echo hello >> /tmp/claude/log.txt",
        &["Bash(echo *)", "Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn input_redirect() {
    let d = check(
        "wc -l < /tmp/data.txt",
        &["Bash(wc *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn heredoc_no_file_access() {
    let d = check(
        "cat <<EOF\nhello\nEOF\n",
        &["Bash(cat *)", "Bash(cat)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn cp_read_and_write() {
    let d = check(
        "cp /tmp/a.txt /tmp/b.txt",
        &["Bash(cp *)", "Read(/tmp/**)", "Write(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
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

#[skuld::test]
fn deny_takes_precedence_for_file() {
    let d = check(
        "cat /etc/shadow",
        &["Bash(cat *)", "Read(/etc/**)"],
        &["Read(/etc/shadow)"],
    );
    assert!(matches!(d, Decision::Deny(_)));
}

#[skuld::test]
fn or_chain() {
    let d = check(
        "true || echo fallback",
        &["Bash(true)", "Bash(echo *)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn negation() {
    let d = check("! true", &["Bash(true)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn dynamic_command_name() {
    let d = check("$CMD arg", &[], &[]);
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn awk_pattern_not_treated_as_file() {
    let d = check("awk '/pattern/{ print }'", &["Bash(awk *)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn awk_double_quoted_pattern_not_treated_as_file() {
    let d = check(r#"awk "/pattern/{ print }""#, &["Bash(awk *)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn awk_with_file_reads_file_not_pattern() {
    let d = check(
        "awk '/p/' /tmp/data.txt",
        &["Bash(awk *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn grep_pattern_not_treated_as_file() {
    let d = check("grep 'pattern'", &["Bash(grep *)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn tr_no_file_access() {
    let d = check("tr 'a-z' 'A-Z'", &["Bash(tr *)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn sed_script_not_treated_as_file() {
    let d = check(
        "sed 's/foo/bar/' /tmp/f.txt",
        &["Bash(sed *)", "Read(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

// ── File-only command tests ─────────────────────────────────────────────────

#[skuld::test]
fn mkdir_allowed_by_write_rule() {
    let d = check("mkdir /tmp/claude/foo", &["Write(/tmp/claude/**)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn mkdir_p_allowed_by_write_rule() {
    let d = check(
        "mkdir -p /tmp/claude/foo/bar",
        &["Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn mkdir_missing_write_rule_asks_for_write_not_bash() {
    let d = check("mkdir /home/user/foo", &[], &[]);
    if let Decision::Ask(ref rules) = d {
        assert!(rules.iter().any(|r| r.contains("Write(")));
        assert!(!rules.iter().any(|r| r.starts_with("Bash(")));
    } else {
        panic!("expected Ask, got {:?}", d);
    }
}

#[skuld::test]
fn mkdir_dynamic_arg_needs_bash_rule() {
    let d = check("mkdir $VAR", &["Write(/tmp/**)"], &[]);
    assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
}

#[skuld::test]
fn mkdir_no_args_needs_bash_rule() {
    let d = check("mkdir", &["Write(/tmp/**)"], &[]);
    assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
}

#[skuld::test]
fn touch_allowed_by_write_rule() {
    let d = check("touch /tmp/claude/foo", &["Write(/tmp/claude/**)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn cat_allowed_by_read_rule() {
    let d = check("cat /tmp/file.txt", &["Read(/tmp/**)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn rm_allowed_by_write_rule() {
    let d = check("rm /tmp/claude/foo.txt", &["Write(/tmp/claude/**)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn source_still_needs_bash_rule() {
    let d = check("source /tmp/script.sh", &["Read(/tmp/**)"], &[]);
    assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
}

#[skuld::test]
fn cp_allowed_by_file_rules() {
    let d = check(
        "cp /tmp/a.txt /tmp/b.txt",
        &["Read(/tmp/**)", "Write(/tmp/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn cp_missing_write_asks_for_write_not_bash() {
    let d = check("cp /tmp/a.txt /home/user/b.txt", &["Read(/tmp/**)"], &[]);
    if let Decision::Ask(ref rules) = d {
        assert!(rules.iter().any(|r| r.contains("Write(")));
        assert!(!rules.iter().any(|r| r.starts_with("Bash(")));
    } else {
        panic!("expected Ask, got {:?}", d);
    }
}

#[skuld::test]
fn grep_with_file_allowed_by_read_rule() {
    let d = check("grep pattern /tmp/data.txt", &["Read(/tmp/**)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn grep_stdin_only_needs_bash_rule() {
    let d = check("grep pattern", &["Read(/tmp/**)"], &[]);
    assert!(matches!(d, Decision::Ask(ref rules) if rules.iter().any(|r| r.starts_with("Bash("))));
}

#[skuld::test]
fn file_only_with_bash_deny_still_denied() {
    let d = check(
        "mkdir /tmp/claude/foo",
        &["Write(/tmp/claude/**)"],
        &["Bash(mkdir *)"],
    );
    assert!(matches!(d, Decision::Deny(_)));
}

#[skuld::test]
fn file_only_with_explicit_bash_rule_still_works() {
    let d = check(
        "mkdir /tmp/claude/foo",
        &["Bash(mkdir *)", "Write(/tmp/claude/**)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn file_only_with_bash_ask_still_asks() {
    let d = check_with_ask(
        "mkdir /tmp/claude/foo",
        &["Write(/tmp/claude/**)"],
        &[],
        &["Bash(mkdir *)"],
    );
    assert!(matches!(d, Decision::Ask(_)));
}

// ── Bare rules (tool-level wildcards) ──

#[skuld::test]
fn bare_read_allows_file_access() {
    let d = check("cat /tmp/file.txt", &["Bash(cat *)", "Read"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn bare_write_allows_file_access() {
    let d = check("echo hi > /tmp/out.txt", &["Bash(echo *)", "Write"], &[]);
    assert_eq!(d, Decision::Allow);
}

// ── Script-runner inline-script sanitization ──

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
fn bash_c_allowed_by_wildcard() {
    let d = check("bash -c 'echo hello'", &["Bash(bash *)"], &[]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
fn bash_script_file_reads() {
    let d = check("bash script.sh", &["Bash(bash *)"], &[]);
    if let Decision::Ask(ref rules) = d {
        assert!(
            rules.iter().any(|r| r.starts_with("Read(")),
            "expected Read rule, got {rules:?}",
        );
    } else {
        panic!("expected Ask for Read rule, got {d:?}");
    }
}

#[skuld::test]
fn bash_script_file_with_read_rule() {
    let d = check("bash script.sh", &["Bash(bash *)", "Read(/tmp/**)"], &[]);
    assert_eq!(d, Decision::Allow);
}

// ── Ask rule semantics ──────────────────────────────────────────────────────

#[skuld::test]
fn ask_rule_overrides_allow_bash() {
    let d = check_with_ask("ls -la", &["Bash(ls *)"], &[], &["Bash(ls *)"]);
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn ask_rule_does_not_override_deny() {
    let d = check_with_ask("rm -rf /tmp/foo", &[], &["Bash(rm *)"], &["Bash(rm *)"]);
    assert!(matches!(d, Decision::Deny(_)));
}

#[skuld::test]
fn ask_rule_overrides_allow_file_read() {
    let d = check_with_ask(
        "cat /tmp/secret.txt",
        &["Bash(cat *)", "Read(/tmp/**)"],
        &[],
        &["Read(/tmp/secret.txt)"],
    );
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn ask_rule_overrides_allow_file_write() {
    let d = check_with_ask(
        "echo hello > /tmp/out.txt",
        &["Bash(echo *)", "Write(/tmp/**)"],
        &[],
        &["Write(/tmp/out.txt)"],
    );
    assert!(matches!(d, Decision::Ask(_)));
}

#[skuld::test]
fn ask_rule_no_match_allows_through() {
    let d = check_with_ask("ls -la", &["Bash(ls *)"], &[], &["Bash(rm *)"]);
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn empty_ask_rules_unchanged_behavior() {
    let d = check_with_ask("ls -la", &["Bash(ls *)"], &[], &[]);
    assert_eq!(d, Decision::Allow);
}

// ── Path canonicalization ────────────────────────────────────────────────────

/// Helper: returns the canonical form of a path (best-effort).
fn c(path: &str) -> String {
    claude_scriptcheck::canonicalize::best_effort_canonicalize(path)
}

#[skuld::test]
fn dotdot_query_path_matches_clean_rule() {
    let d = check(
        "cat ../file.txt",
        &["Read(/**)", "Bash(cat *)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn rule_with_dotdot_matches_normalized_query() {
    let d = check(
        "cat /tmp/file.txt",
        &[&format!("Read({}/nonexistent/../**)", c("/tmp")), "Bash(cat *)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn dot_in_query_path_resolved() {
    let d = check(
        "cat ./file.txt",
        &[&format!("Read({}/**)", c("/tmp")), "Bash(cat *)"],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

#[skuld::test]
fn relative_path_in_query_canonicalized() {
    let d = check(
        "mkdir subdir/foo",
        &[&format!("Write({}/**)", c("/tmp"))],
        &[],
    );
    assert_eq!(d, Decision::Allow);
}
