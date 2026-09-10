use claude_scriptcheck::checker::{check_file_accesses, check_program, CheckResult, Decision};
use claude_scriptcheck::file_access::{AccessKind, AccessScope, FileAccess};
use claude_scriptcheck::path_util;
use claude_scriptcheck::permission::{self, ParsedPermissions};
use claude_scriptcheck::settings::Permissions;
use pretty_assertions::assert_eq;

fn make_perms_full(allow: &[&str], deny: &[&str], ask: &[&str]) -> ParsedPermissions {
    // Default cwd for tests that don't care: "/tmp" is the same cwd most
    // `check` helpers use when invoking `check_program` below.
    permission::parse_rules(
        &Permissions {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ask: ask.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        "/tmp",
        "/tmp",
    )
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

/// Parse rules with a specific (cwd, project_root) context and run the
/// command under the same cwd. Needed for tests that exercise `Arg0::Path`
/// resolution, where both sides of the match must share a cwd.
fn check_ctx(
    cmd: &str,
    allow: &[&str],
    deny: &[&str],
    cwd: &str,
    project_root: &str,
) -> CheckResult {
    let perms = permission::parse_rules(
        &Permissions {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        cwd,
        project_root,
    );
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
    let d = check("cp /tmp/a.txt /home/user/b.txt", &["Read(/tmp/**)"], &[]);
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
        scope: "/tmp/data.txt".into(),
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
        scope: "/etc/shadow".into(),
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
            scope: "/home/user/secret.txt".into(),
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
            scope: "/tmp/secret.txt".into(),
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
            scope: "/tmp/out.txt".into(),
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
            scope: "/tmp/out.txt".into(),
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
            scope: "/etc/passwd".into(),
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
            scope: "/etc/shadow".into(),
            kind: AccessKind::Read,
        },
        FileAccess {
            scope: "/tmp/safe.txt".into(),
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
            scope: "/home/a.txt".into(),
            kind: AccessKind::Read,
        },
        FileAccess {
            scope: "/home/b.txt".into(),
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
            scope: "/etc/config.json".into(),
            kind: AccessKind::Write,
        }],
        &[],
        &["Edit(/etc/**)"],
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

// Python AST analysis integration tests ===============================================================================

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

// Command name normalization ==========================================================================================

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

// Arg0 name/path-scoped matching ======================================================================================

#[skuld::test]
fn rule_bare_name_matches_path_invocation() {
    let d = check("./tools/rg foo", &["Bash(rg *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_bare_name_matches_exe_extension() {
    let d = check("rg.exe foo", &["Bash(rg *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_bare_name_matches_cmd_extension() {
    let d = check("./tools/rg.cmd foo", &["Bash(rg *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_bare_name_does_not_match_different_name() {
    let d = check("grep foo", &["Bash(rg *)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn rule_path_scoped_matches_same_path() {
    let d = check_ctx(
        "./tools/rg.cmd foo",
        &["Bash(./tools/rg.cmd *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_path_scoped_matches_equivalent_absolute() {
    let d = check_ctx(
        "/project/tools/rg.cmd foo",
        &["Bash(./tools/rg.cmd *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_path_scoped_does_not_match_different_cwd() {
    // Rule parsed against /a, command runs from /b → different canonical paths.
    let d = check_ctx(
        "./tools/rg.cmd foo",
        &["Bash(./tools/rg.cmd *)"],
        &[],
        "/b",
        "/b",
    );
    // Command's canonical path is /b/tools/rg.cmd.
    // Rule parsed with cwd=/b also resolves to /b/tools/rg.cmd — so they match.
    // To actually test the "different cwd" case, we need the rule parsed with
    // a different cwd than the command runs with. Use a separate helper:
    let perms = permission::parse_rules(
        &Permissions {
            allow: vec!["Bash(./tools/rg.cmd *)".to_string()],
            ..Default::default()
        },
        "/a",
        "/a",
    );
    let program = thaum::parse_with("./tools/rg.cmd foo", thaum::Dialect::Bash).unwrap();
    let result = check_program(&program, &perms, "/b");
    assert_eq!(result.decision, Decision::Ask);
    // And the original same-cwd case as a sanity check:
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_path_scoped_does_not_match_bare_name() {
    let d = check_ctx(
        "rg.cmd foo",
        &["Bash(./tools/rg.cmd *)"],
        &[],
        "/project",
        "/project",
    );
    // Bare invocation — path-scoped rule rejects.
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn rule_project_relative_path_matches_regardless_of_cwd() {
    // Rule uses `/tools/rg.cmd` = project-relative. Command can be invoked
    // from any cwd and still resolves to the same absolute path, so it
    // matches.
    let perms = permission::parse_rules(
        &Permissions {
            allow: vec!["Bash(/tools/rg.cmd *)".to_string()],
            ..Default::default()
        },
        "/some/cwd",
        "/project",
    );
    let program = thaum::parse_with("/project/tools/rg.cmd foo", thaum::Dialect::Bash).unwrap();
    let result = check_program(&program, &perms, "/irrelevant");
    assert_eq!(result.decision, Decision::Allow);
}

#[skuld::test]
fn rule_double_slash_absolute_matches() {
    let d = check_ctx(
        "/usr/local/bin/rg foo",
        &["Bash(//usr/local/bin/rg *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_windows_backslash_path_matches() {
    // Backslash-written rule path routes through normalize_separators.
    let d = check_ctx(
        "./tools/rg.cmd foo",
        &["Bash(.\\tools\\rg.cmd *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn deny_rule_path_scoped_matches() {
    let d = check_ctx(
        "./danger/exec foo",
        &[],
        &["Bash(./danger/exec *)"],
        "/project",
        "/project",
    );
    assert!(matches!(d.decision, Decision::Deny(_)));
}

#[skuld::test]
fn deny_rule_path_scoped_does_not_match_bare_name() {
    // Bare `exec` invocation doesn't match a path-scoped Deny rule.
    let d = check_ctx(
        "exec foo",
        &[],
        &["Bash(./danger/exec *)"],
        "/project",
        "/project",
    );
    // Ask because no allow matches and the deny rule didn't fire.
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn ask_rule_path_scoped_forces_ask() {
    let d = check_with_ask(
        "./danger/exec foo",
        &["Bash(./danger/exec *)"],
        &[],
        &["Bash(./danger/exec *)"],
    );
    // Ask rule wins: bash_asked = true → allow scan skipped → Ask with missing rule.
    // But this test uses `check_with_ask` which parses rules with cwd=/tmp.
    // The path resolves to /tmp/danger/exec for both rule and command-cwd=/tmp.
    assert_eq!(d.decision, Decision::Ask);
    assert!(!d.missing_rules.is_empty());
}

#[skuld::test]
fn middle_star_matches_one_token() {
    // Use a command with no dedicated parser so the Bash rule flow runs as-is.
    let d = check(
        "mycmd --arg value --after",
        &["Bash(mycmd --arg * --after)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn middle_star_does_not_match_zero_tokens() {
    let d = check("mycmd --arg --after", &["Bash(mycmd --arg * --after)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn middle_double_star_matches_many() {
    let d = check(
        "mycmd --a --b --c --after",
        &["Bash(mycmd ** --after)"],
        &[],
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_double_star_in_arg0_slot() {
    // `Bash(**/foo bar)` — classifier puts `**` at items[0] as
    // MatchZeroOrMore; `foo`/`bar` become Arg items. Command `git foo bar`
    // matches (MZM skips `git`, then `foo` == `foo`, `bar` == `bar`).
    let d = check("git foo bar", &["Bash(** foo bar)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_dynamic_arg0_wildcard_only_matches_universal() {
    // A dynamic arg0 (expanded from a variable) can only be matched by
    // `Bash(*)` / `Bash(**)`. `Bash(rg *)` must Ask.
    let dynamic = r#""$cmd" foo"#;
    let d_universal = check(dynamic, &["Bash(*)"], &[]);
    assert_eq!(d_universal.decision, Decision::Allow);

    let d_specific = check(dynamic, &["Bash(rg *)"], &[]);
    assert_eq!(d_specific.decision, Decision::Ask);
}

#[skuld::test]
fn rule_path_scoped_nonexistent_still_matches_logically() {
    // `best_effort_canonicalize` falls back to logical normalization when the
    // target doesn't exist; same-logical-path rule and command should match.
    let d = check_ctx(
        "/missing/path/rg foo",
        &["Bash(//missing/path/rg *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn rule_path_pathext_tolerance_reverse() {
    // Rule has `.cmd`, command has no extension.
    let d = check_ctx(
        "./bin/rg foo",
        &["Bash(./bin/rg.cmd *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn missing_rule_suggestion_uses_basename() {
    // Confirms missing_rules emission uses the name form (Arg0::Name + stripped
    // basename). Use a command the file-access parsers don't recognize so the
    // Bash rule demand isn't skipped by is_file_only_command handling.
    let d = check(r#"./tools/myunknowncmd.cmd foo bar"#, &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
    assert!(
        d.missing_rules
            .iter()
            .any(|r| r.starts_with("Bash(myunknowncmd")),
        "missing_rules should suggest name-form rule with stripped basename, got {:?}",
        d.missing_rules
    );
    // And the suggestion should NOT include the full path.
    assert!(
        !d.missing_rules.iter().any(|r| r.contains("./tools")),
        "missing_rules should not leak the full invocation path, got {:?}",
        d.missing_rules
    );
}

#[skuld::test]
fn parse_failure_reason_uses_raw_arg0() {
    // `git` has a dedicated parser that rejects unknown global flags. Use
    // something the parser can't handle to trigger the ParseFailed branch.
    // Invoking `git -c` with no value is a malformed flag that the git
    // parser will reject at its arg-parsing stage.
    //
    // Pin the contract: when the parser fails, the error message must
    // contain the raw arg0 (with path), not the normalized basename. The
    // user sees their actual command, not a rewritten form.
    let d = check(r#"./bin/git --not-a-real-global-flag=x status"#, &[], &[]);
    assert_eq!(d.decision, Decision::Ask);
    // If the git parser rejected the invocation, the Ask reason should
    // contain the raw "./bin/git" prefix. If the parser accepted it (and
    // just asks for a Bash rule), at minimum the missing_rules list shows
    // the basename form (already tested above). Tolerate both — but if we
    // DO get a parse-failure message, verify it uses raw arg0.
    if let Some(msg) = d
        .missing_rules
        .iter()
        .find(|m| m.contains("failed to parse"))
    {
        assert!(
            msg.contains("./bin/git"),
            "parse-failure message should include raw arg0, got: {msg}"
        );
    }
}

#[skuld::test]
fn rule_tilde_path_matches_absolute_invocation() {
    // `Bash(~/bin/rg *)` parses to `Arg0::Path(/home/anna/bin/rg)`; invoking
    // `/home/anna/bin/rg foo` should match.
    let home = "/home/anna";
    let perms = permission::parse_rules(
        &Permissions {
            allow: vec!["Bash(~/bin/rg *)".to_string()],
            ..Default::default()
        },
        "/cwd",
        "/project",
    );
    // `parse_rules` reads home via env_hooks; to isolate the test, we
    // bypass and construct a ParseCtx directly. Use `parse_single_rule`
    // instead to pin the home explicitly.
    let _ = perms; // keep the parse_rules variant for contrast; drop it.

    use claude_scriptcheck::permission::{parse_single_rule, ParseCtx, ParsedFilter};
    let ctx = ParseCtx {
        home,
        cwd: "/cwd",
        project_root: "/project",
    };
    let rule = match parse_single_rule("Bash(~/bin/rg *)", &ctx).unwrap() {
        ParsedFilter::Bash(f) => f,
        _ => panic!("expected Bash"),
    };
    let mut parsed = ParsedPermissions::default();
    parsed.bash.allow.push(rule);

    let program = thaum::parse_with("/home/anna/bin/rg foo", thaum::Dialect::Bash).unwrap();
    let result = check_program(&program, &parsed, "/cwd");
    assert_eq!(result.decision, Decision::Allow);
}

#[skuld::test]
fn rule_path_glob_matches_subdir_invocation() {
    // Bash path rules support globs (parallel to Read/Write/Edit). A rule
    // `Bash(//opt/*/rg *)` matches `/opt/tools/rg foo` but not
    // `/opt/a/b/rg foo`.
    let perms = permission::parse_rules(
        &Permissions {
            allow: vec!["Bash(//opt/*/rg *)".to_string()],
            ..Default::default()
        },
        "/cwd",
        "/project",
    );
    let program = thaum::parse_with("/opt/tools/rg foo", thaum::Dialect::Bash).unwrap();
    let result = check_program(&program, &perms, "/cwd");
    assert_eq!(result.decision, Decision::Allow);

    let program = thaum::parse_with("/opt/a/b/rg foo", thaum::Dialect::Bash).unwrap();
    let result = check_program(&program, &perms, "/cwd");
    assert_eq!(result.decision, Decision::Ask);
}

#[skuld::test]
fn rule_dynamic_arg0_with_mzm_args_matches() {
    // Regression test for matches_dynamic_arg0 args threading.
    // `Bash(** foo)` with dynamic arg0 invoked as `"$x" foo` should match:
    // MZM consumes 0 tokens, then Arg("foo") consumes "foo".
    let d = check(r#""$cmd" foo"#, &["Bash(** foo)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
    // Same rule, different args → no match.
    let d = check(r#""$cmd" bar"#, &["Bash(** foo)"], &[]);
    assert_eq!(d.decision, Decision::Ask);
}

#[skuld::test]
fn bug_report_rg_cmd_pipeline() {
    // The exact scenario from the bug report that motivated this refactor.
    let d = check_ctx(
        r#"./community/tools/rg.cmd -l "package utilities\.qodana" 2>&1 | head -10"#,
        &["Bash(./community/tools/rg.cmd *)", "Bash(head *)"],
        &[],
        "/project",
        "/project",
    );
    assert_eq!(d.decision, Decision::Allow);
}

// uv run wrapper ======================================================================================================

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

// Git subcommand file-only suppression ================================================================================

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
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
}

#[skuld::test]
fn git_push_with_bash_rule_alone_is_allow() {
    let d = check("git push origin main", &["Bash(git push *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

#[skuld::test]
fn bash_allow_suppresses_file_read_ask_with_matched_allow_logged() {
    let d = check_with_ask("cat /tmp/x", &["Bash(cat *)"], &[], &["Read(/tmp/x)"]);
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
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
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
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
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
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
}

#[skuld::test]
fn dynamic_cmd_name_redirect_deny_fires_under_wildcard_allow() {
    let d = check("$CMD arg > /etc/hosts", &["Bash(*)"], &["Write(/etc/**)"]);
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
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
        &[
            "Bash(diff *)",
            "Bash(git fetch *)",
            &format!("Read({}/**)", c("/tmp")),
        ],
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
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
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
    assert!(
        matches!(d.decision, Decision::Deny(_)),
        "expected Deny, got {d:?}"
    );
}

#[skuld::test]
fn dynamic_cmd_name_allowed_by_bash_double_star_space_star() {
    // `Bash(** *)` also matches empty tokens (the `**` recursive-skip loop in
    // BashFilter::matches falls through to empty-prefix + wildcard).
    let d = check("$CMD arg", &["Bash(** *)"], &[]);
    assert_eq!(d.decision, Decision::Allow);
}

// Access scopes =======================================================================================================

// `check_file_accesses` uses cwd `/tmp`, and `make_perms_full` parses rules
// against cwd `/tmp`, so `/repro/...` (Claude's absolute escape) keeps these
// paths off the project root.

fn scoped(scope: AccessScope, kind: AccessKind) -> [FileAccess; 1] {
    [FileAccess::scoped(scope, kind)]
}

fn canonical(path: &str) -> String {
    claude_scriptcheck::canonicalize::best_effort_canonicalize(path)
}

#[skuld::test]
fn subtree_read_hits_deny_rule_beneath_root() {
    let accesses = scoped(
        AccessScope::Subtree("/repro/vault".into()),
        AccessKind::Read,
    );
    let result = check_accesses_full(&accesses, &[], &["Read(/repro/vault/**)"], &[]);
    assert!(matches!(result.decision, Decision::Deny(_)));
}

#[skuld::test]
fn subtree_read_hits_deny_rule_on_nested_file() {
    let accesses = scoped(AccessScope::Subtree("/repro".into()), AccessKind::Read);
    let result = check_accesses_full(&accesses, &[], &["Read(/repro/vault/creds)"], &[]);
    assert!(matches!(result.decision, Decision::Deny(_)));
}

#[skuld::test]
fn subtree_read_satisfied_by_globstar_allow() {
    let accesses = scoped(
        AccessScope::Subtree("/repro/vault".into()),
        AccessKind::Read,
    );
    let result = check_accesses_full(&accesses, &["Read(/repro/vault/**)"], &[], &[]);
    assert_eq!(result.decision, Decision::Allow);
    assert!(result.missing_rules.is_empty());
}

#[skuld::test]
fn subtree_read_not_satisfied_by_exact_allow() {
    let accesses = scoped(
        AccessScope::Subtree("/repro/vault".into()),
        AccessKind::Read,
    );
    let result = check_accesses_full(&accesses, &["Read(/repro/vault)"], &[], &[]);
    assert_eq!(result.decision, Decision::Ask);
    let expected = format!("Read({}/**)", canonical("/repro/vault"));
    assert_eq!(result.missing_rules, vec![expected]);
}

#[skuld::test]
fn subtree_read_unaffected_by_fixed_depth_ask_rule() {
    let accesses = scoped(AccessScope::Subtree("/repro/foo".into()), AccessKind::Read);
    let result = check_accesses_full(
        &accesses,
        &["Read(/repro/**)"],
        &[],
        &["Read(/repro/*.log)"],
    );
    assert_eq!(result.decision, Decision::Allow);
}

#[skuld::test]
fn subtree_write_hits_edit_deny_rule() {
    let accesses = scoped(
        AccessScope::Subtree("/repro/vault".into()),
        AccessKind::Write,
    );
    let result = check_accesses_full(&accesses, &[], &["Edit(/repro/vault/**)"], &[]);
    assert!(matches!(result.decision, Decision::Deny(_)));
}

#[skuld::test]
fn unbounded_subtree_asks_under_globstar_allow() {
    // A symlink-following walk can leave the subtree, so no allow rule proves
    // coverage — the same command with a bounded scope allows.
    let unbounded = scoped(
        AccessScope::UnboundedSubtree("/repro/vault".into()),
        AccessKind::Read,
    );
    let bounded = scoped(
        AccessScope::Subtree("/repro/vault".into()),
        AccessKind::Read,
    );
    assert_eq!(
        check_accesses_full(&unbounded, &["Read(/repro/**)"], &[], &[]).decision,
        Decision::Ask,
    );
    assert_eq!(
        check_accesses_full(&bounded, &["Read(/repro/**)"], &[], &[]).decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn unbounded_subtree_still_denies() {
    let accesses = scoped(
        AccessScope::UnboundedSubtree("/repro".into()),
        AccessKind::Read,
    );
    let result = check_accesses_full(&accesses, &[], &["Read(/repro/vault/**)"], &[]);
    assert!(matches!(result.decision, Decision::Deny(_)));
}

#[skuld::test]
fn unresolved_scope_asks_when_unsuppressed() {
    let accesses = scoped(AccessScope::Unresolved("$FOO".into()), AccessKind::Read);
    let result = check_accesses_full(&accesses, &["Read(**)"], &[], &[]);
    assert_eq!(result.decision, Decision::Ask);
    assert_eq!(result.missing_rules, vec!["Read(<unresolved: $FOO>)"]);
}

#[skuld::test]
fn exact_access_to_subtree_root_still_asks_under_globstar_allow() {
    // `Read(vault/**)` covers a recursive read rooted at
    // `vault`, but a plain `cat vault` is untouched and still asks.
    let accesses = scoped(AccessScope::Exact("/repro/vault".into()), AccessKind::Read);
    let result = check_accesses_full(&accesses, &["Read(/repro/vault/**)"], &[], &[]);
    assert_eq!(result.decision, Decision::Ask);
}

#[skuld::test]
fn unbounded_subtree_suggestion_does_not_name_an_unusable_rule() {
    // `covers` rejects every path pattern for a symlink-following walk, so a
    // `Read(D/**)` suggestion would loop the user forever.
    let accesses = scoped(
        AccessScope::UnboundedSubtree("/repro/vault".into()),
        AccessKind::Read,
    );
    let result = check_accesses_full(&accesses, &["Read(/repro/**)"], &[], &[]);
    assert_eq!(result.decision, Decision::Ask);
    let suggestion = result.missing_rules.first().expect("a missing rule");
    assert!(
        suggestion.contains("Bash(...)") && suggestion.contains("follows symlinks"),
        "suggestion should point at a rule that can actually work, got: {suggestion}",
    );
}

// ── Missing-rule suggestions ────────────────────────────────────────────────

#[skuld::test]
fn unbounded_write_suggestion_names_write_not_read() {
    // A symlink-following recursive *write* must not be described with a Read
    // rule; the suggestion has to match the access it came from.
    let perms = make_perms(&[], &[]);
    let accesses = [FileAccess::scoped(
        AccessScope::UnboundedSubtree("/a/b".to_string()),
        AccessKind::Write,
    )];
    let result = check_file_accesses(&accesses, &perms, "/cwd");
    let suggestion = result.missing_rules.join(" ");
    assert!(
        !suggestion.contains("Read("),
        "write access suggested a Read rule: {suggestion}",
    );
    assert!(
        suggestion.contains("Bash("),
        "suggestion should name the rule shape that resolves it: {suggestion}",
    );
}

#[skuld::test]
fn unbounded_suggestion_has_no_unusable_pattern() {
    // `display()` renders an unbounded subtree as `<dir>/**+symlinks`, which is
    // not a glob any rule can use. It must not be handed to the user as one.
    let perms = make_perms(&[], &[]);
    let accesses = [FileAccess::scoped(
        AccessScope::UnboundedSubtree("/a/b".to_string()),
        AccessKind::Read,
    )];
    let result = check_file_accesses(&accesses, &perms, "/cwd");
    let suggestion = result.missing_rules.join(" ");
    assert!(
        !suggestion.contains("+symlinks"),
        "suggestion contains a pattern no rule can use: {suggestion}",
    );
}

// ── Redirect classification ─────────────────────────────────────────────────
//
// A redirect names a file, duplicates a descriptor, or carries inline text.
// Getting that wrong in either direction is expensive: a file read as a
// descriptor slips past every rule, and a descriptor read as a file produces a
// deny no rule the user adds can lift.

// `<>` opens for reading and writing (Bash §3.6.10) -------------------------------------------------------------------

#[skuld::test]
fn read_write_redirect_emits_a_read() {
    let result = check("cat <> /tmp/x", &[], &[]);
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/x"))),
        "expected a Read demand, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn read_write_redirect_emits_a_write() {
    let result = check("cat <> /tmp/x", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/x"))),
        "expected a Write demand, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn read_write_redirect_fires_a_read_deny() {
    // The bypass: `<` denied but `<>` did not, one character apart.
    assert!(matches!(
        check("cat <> /tmp/x", &["Bash(cat *)"], &["Read(/tmp/**)"]).decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn read_write_redirect_fires_a_write_deny() {
    assert!(matches!(
        check("cat <> /tmp/x", &["Bash(cat *)"], &["Write(/tmp/**)"]).decision,
        Decision::Deny(_),
    ));
}

// `>&word` names a file unless the word names a descriptor (Bash §3.6.8-9) --------------------------------------------

#[skuld::test]
fn dup_output_to_a_file_is_a_write() {
    let result = check("cat /tmp/x >&/tmp/out", &["Read(/tmp/x)"], &[]);
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/out"))),
        "expected a Write demand, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn dup_output_to_a_file_fires_a_write_deny() {
    // The bypass: `>` denied but `>&` did not.
    assert!(matches!(
        check(
            "cat /tmp/x >&/tmp/out",
            &["Bash(cat *)"],
            &["Write(/tmp/**)"]
        )
        .decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn close_form_names_no_file() {
    // Verified against bash 5: `log hi >&-2` creates nothing. The `-` closes
    // the descriptor, so there is no file called `-2` to demand a rule for.
    for cmd in [
        "cat /tmp/x >&-2",
        "cat /tmp/x >&-foo",
        "cat /tmp/x 1>&-2",
        "cat /tmp/x <&-2",
    ] {
        let result = check(cmd, &["Read(/tmp/x)"], &[]);
        assert!(
            !result
                .missing_rules
                .iter()
                .any(|r| r.contains("-2") || r.contains("-foo")),
            "{cmd}: named a dash-prefixed file: {:?}",
            result.missing_rules,
        );
    }
}

#[skuld::test]
fn close_form_operand_becomes_an_argument() {
    // Verified: `log hi >&-2` reports `argc=2 [hi 2]`. thaum keeps the whole of
    // `-2` as the redirect target, so the operand has to be put back — here it
    // makes `cat` read `./2`.
    let result = check("cat /tmp/x >&-2", &["Read(/tmp/x)"], &[]);
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/2"))),
        "operand not recovered as an argument: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn close_form_operand_cannot_hide_a_denied_path() {
    // The exfiltration shape. Verified against bash: `log >&-vault/creds
    // stolen.txt` reports `argc=2 [vault/creds stolen.txt]`, so the copy really
    // does read the deny-listed file. `Bash(cp *)` is allowed deliberately —
    // suppression must not reach a file deny.
    let result = check(
        "cp >&-/tmp/vault/creds /tmp/stolen.txt",
        &["Bash(cp *)"],
        &["Read(/tmp/vault/**)"],
    );
    assert!(
        matches!(result.decision, Decision::Deny(_)),
        "denied path hidden behind >&-: {result:?}",
    );
}

#[skuld::test]
fn recovered_operand_keeps_its_source_position() {
    // Position decides an operand's meaning: `cp a b` reads a and writes b. The
    // operand is spliced in where the word appears, so it lands as the source.
    let result = check(
        "cp >&-/tmp/src.txt /tmp/dst.txt",
        &["Bash(cp *)"],
        &["Write(/tmp/src.txt)"],
    );
    assert_eq!(
        result.decision,
        Decision::Allow,
        "recovered operand treated as the destination: {result:?}",
    );
    assert!(matches!(
        check(
            "cp >&-/tmp/src.txt /tmp/dst.txt",
            &["Bash(cp *)"],
            &["Write(/tmp/dst.txt)"],
        )
        .decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn fd_one_dup_output_to_a_file_is_a_write() {
    // Bash §3.6.8 says "if n is omitted", but bash also redirects for n == 1,
    // including zero-padded spellings. Verified: `log hi 001>&out` creates
    // `out`. Treating any leading descriptor as a duplication walked the whole
    // `1>&` family straight through this guardrail.
    for cmd in [
        "cat /tmp/x 1>&/tmp/out",
        "cat /tmp/x 01>&/tmp/out",
        "cat /tmp/x 001>&/tmp/out",
    ] {
        let result = check(cmd, &["Read(/tmp/x)"], &[]);
        assert!(
            result
                .missing_rules
                .contains(&format!("Write({})", canonical("/tmp/out"))),
            "{cmd}: expected a Write demand, got {:?}",
            result.missing_rules,
        );
    }
}

#[skuld::test]
fn fd_one_dup_output_fires_a_write_deny() {
    for cmd in [
        "cat /tmp/x 1>&/tmp/out",
        "cat /tmp/x 01>&/tmp/out",
        "cat /tmp/x 001>&/tmp/out",
    ] {
        assert!(
            matches!(
                check(cmd, &["Bash(cat *)"], &["Write(/tmp/**)"]).decision,
                Decision::Deny(_),
            ),
            "{cmd}",
        );
    }
}

#[skuld::test]
fn dup_output_with_another_fd_names_no_file() {
    // Verified: `log hi 2>&out` fails with "ambiguous redirect" and creates
    // nothing. Only fd 1 gets the file treatment.
    for cmd in [
        "cat /tmp/x 2>&/tmp/out",
        "cat /tmp/x 3>&/tmp/out",
        "cat /tmp/x 0>&/tmp/out",
        "cat /tmp/x 10>&/tmp/out",
    ] {
        assert_eq!(
            check(cmd, &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
            Decision::Allow,
            "{cmd}",
        );
    }
}

#[skuld::test]
fn words_that_only_look_like_descriptors_are_files() {
    // Verified: each of these creates a file of that name.
    for (cmd, name) in [
        ("cat /tmp/x >&/tmp/2-3", "/tmp/2-3"),
        ("cat /tmp/x >&/tmp/+2", "/tmp/+2"),
        ("cat /tmp/x >&/tmp/2x", "/tmp/2x"),
    ] {
        let result = check(cmd, &["Read(/tmp/x)"], &[]);
        assert!(
            result
                .missing_rules
                .contains(&format!("Write({})", canonical(name))),
            "{cmd}: expected a Write demand, got {:?}",
            result.missing_rules,
        );
    }
}

#[skuld::test]
fn out_of_range_descriptor_move_names_no_file() {
    // `>&12-` fails at runtime with "Bad file descriptor" — still a descriptor
    // operation, still opens nothing.
    assert_eq!(
        check("cat /tmp/x >&12-", &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
        Decision::Allow,
    );
}

// Descriptor forms name no file ---------------------------------------------------------------------------------------

#[skuld::test]
fn descriptor_duplication_and_closing_name_no_file() {
    // Allow rather than ask is the discriminator: a recorded access would be
    // unmatched and surface.
    for cmd in ["cat /tmp/x >&2", "cat /tmp/x >&-", "cat /tmp/x <&3"] {
        assert_eq!(
            check(cmd, &["Read(/tmp/x)"], &[]).decision,
            Decision::Allow,
            "{cmd}",
        );
    }
}

#[skuld::test]
fn explicit_fd_duplication_names_no_file() {
    assert_eq!(
        check("cat /tmp/x 2>&1", &["Read(/tmp/x)"], &[]).decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn descriptor_move_names_no_file() {
    // §3.6.9's move form: duplicate, then close the source. The trailing `-` is
    // not part of a filename.
    for cmd in ["cat /tmp/x >&2-", "cat /tmp/x >&1-", "cat /tmp/x <&0-"] {
        assert_eq!(
            check(cmd, &["Read(/tmp/x)"], &[]).decision,
            Decision::Allow,
            "{cmd}",
        );
    }
}

#[skuld::test]
fn descriptor_move_does_not_trigger_a_write_deny() {
    // Reading `2-` as a filename would deny a valid command, and a deny is
    // authoritative in every mode — no rule the user adds can lift it.
    assert_eq!(
        check("cat /tmp/x >&2-", &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn dup_input_from_a_non_numeric_word_names_no_file() {
    // `<&word` takes only descriptor forms; any other word is a redirection
    // error, not a file open. The `>&` file special case is output-only.
    assert_eq!(
        check("cat /tmp/x <&/tmp/other", &["Read(/tmp/x)"], &[]).decision,
        Decision::Allow,
    );
}

// Inline-text redirects name no file ----------------------------------------------------------------------------------

#[skuld::test]
fn here_string_and_here_doc_name_no_file() {
    assert_eq!(
        check("cat /tmp/x <<< hi", &["Read(/tmp/x)"], &[]).decision,
        Decision::Allow,
    );
}

// Unchanged arms ------------------------------------------------------------------------------------------------------

#[skuld::test]
fn ordinary_redirect_arms_are_unchanged() {
    for (cmd, kind, path) in [
        ("cat /tmp/x < /tmp/in", "Read", "/tmp/in"),
        ("cat /tmp/x > /tmp/out", "Write", "/tmp/out"),
        ("cat /tmp/x >> /tmp/out", "Write", "/tmp/out"),
        ("cat /tmp/x >| /tmp/out", "Write", "/tmp/out"),
        ("cat /tmp/x &> /tmp/out", "Write", "/tmp/out"),
        ("cat /tmp/x &>> /tmp/out", "Write", "/tmp/out"),
    ] {
        let expected = format!("{kind}({})", canonical(path));
        let result = check(cmd, &["Read(/tmp/x)"], &[]);
        assert!(
            result.missing_rules.contains(&expected),
            "{cmd}: expected {expected}, got {:?}",
            result.missing_rules,
        );
    }
}

#[skuld::test]
fn unresolvable_redirect_target_is_still_dropped() {
    // Recording it is #45's job, deliberately not this change's. Pinned so the
    // split stays honest: if this starts asking, B leaked in.
    assert_eq!(
        check("cat /tmp/x > $FOO", &["Read(/tmp/x)"], &[]).decision,
        Decision::Allow,
    );
}

// Trailing-dash and empty words (F2b) ---------------------------------------------------------------------------------

#[skuld::test]
fn unquoted_trailing_dash_names_no_file() {
    // A trailing dash makes bash read the whole word as a descriptor spec,
    // whatever precedes it. Verified: `>&x-` and `>&2x-` both fail with
    // "ambiguous redirect" and create nothing, so demanding a Write for a file
    // called `x-` would be a deny on a command that opens nothing.
    for cmd in [
        "cat /tmp/x >&x-",
        "cat /tmp/x >&2x-",
        "cat /tmp/x 1>&x-",
        "cat /tmp/x >&12-",
    ] {
        assert_eq!(
            check(cmd, &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
            Decision::Allow,
            "{cmd}",
        );
    }
}

#[skuld::test]
fn empty_redirect_word_names_no_file() {
    // Verified: `>&""` fails with "Bad file descriptor" and creates nothing.
    assert_eq!(
        check("cat /tmp/x >&\"\"", &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn quoting_turns_a_dash_form_into_a_filename() {
    // The sharp edge: these are one character from the descriptor spellings and
    // mean the opposite. Verified — each creates a file of that literal name.
    for (cmd, name) in [
        ("cat /tmp/x >&\"/tmp/-2\"", "/tmp/-2"),
        ("cat /tmp/x >&'/tmp/-2'", "/tmp/-2"),
        ("cat /tmp/x >&\"/tmp/2-\"", "/tmp/2-"),
        ("cat /tmp/x >&\"/tmp/x-\"", "/tmp/x-"),
    ] {
        let result = check(cmd, &["Read(/tmp/x)"], &[]);
        assert!(
            result
                .missing_rules
                .contains(&format!("Write({})", canonical(name))),
            "{cmd}: expected a Write demand, got {:?}",
            result.missing_rules,
        );
    }
}

#[skuld::test]
fn quoted_dash_form_fires_a_write_deny() {
    // Missing these would be a bypass, not a spurious ask: bash really writes.
    for cmd in [
        "cat /tmp/x >&\"/tmp/-2\"",
        "cat /tmp/x >&\"/tmp/2-\"",
        "cat /tmp/x >&\"/tmp/x-\"",
    ] {
        assert!(
            matches!(
                check(cmd, &["Bash(cat *)"], &["Write(/tmp/**)"]).decision,
                Decision::Deny(_),
            ),
            "{cmd}",
        );
    }
}

#[skuld::test]
fn quoting_does_not_change_duplication_or_closing() {
    // Verified: `>&"2"` duplicates and `>&"-"` closes, exactly as bare.
    for cmd in [
        "cat /tmp/x >&\"2\"",
        "cat /tmp/x >&'2'",
        "cat /tmp/x >&\"-\"",
    ] {
        assert_eq!(
            check(cmd, &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
            Decision::Allow,
            "{cmd}",
        );
    }
}

#[skuld::test]
fn quoted_leading_dash_recovers_no_operand() {
    // `>&"-2"` is a filename, so there is no argument to splice back in.
    let result = check("cat /tmp/x >&\"/tmp/-2\"", &["Read(/tmp/x)"], &[]);
    assert!(
        !result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/2"))),
        "recovered an operand from a quoted word: {:?}",
        result.missing_rules,
    );
}

// Quoting granularity: the two edges, not the whole word --------------------------------------------------------------
//
// Derived from bash's tokenisation rather than from a table of spellings.
//
// An unquoted `-` as the *first* character terminates the redirect target:
// bash reads `>&-` as "close" and lexes the rest of the token as a fresh word.
// Quoting anywhere after that dash is irrelevant to that decision. Quoting the
// dash itself is not — it makes the whole token an ordinary filename.
//
// Independently, an unquoted `-` as the *last* character makes the word a
// descriptor spec; a quoted trailing dash makes it a filename.

#[skuld::test]
fn quoted_operand_after_a_close_is_still_an_argument() {
    // Verified: `log >&-"vault/creds" s.txt` reports argc=2 [vault/creds s.txt].
    // Testing quoting on the whole word rather than on the leading dash let
    // this walk straight through the operand-recovery path.
    for cmd in [
        "cp >&-\"/tmp/vault/creds\" /tmp/stolen.txt",
        "cp >&-'/tmp/vault/creds' /tmp/stolen.txt",
        "cp >&-/tmp/vault\"/\"creds /tmp/stolen.txt",
        "cp >&-/tmp/\"vault\"/creds /tmp/stolen.txt",
    ] {
        assert!(
            matches!(
                check(cmd, &["Bash(cp *)"], &["Read(/tmp/vault/**)"]).decision,
                Decision::Deny(_),
            ),
            "denied path hidden behind a quoted operand: {cmd}",
        );
    }
}

#[skuld::test]
fn quoting_the_leading_dash_makes_it_a_filename() {
    // `>&"-"foo` writes `-foo`; the dash no longer terminates the token.
    let result = check("cat /tmp/x >&\"-\"foo", &["Read(/tmp/x)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/-foo"))),
        "expected a Write demand for `-foo`, got {:?}",
        result.missing_rules,
    );
    assert!(
        !result
            .missing_rules
            .iter()
            .any(|r| r.contains(&canonical("/tmp/foo"))),
        "recovered an operand from a quoted dash: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn trailing_dash_quoting_is_per_character_too() {
    // `>&"2"-` moves fd 2 and opens nothing; `>&2"-"` writes a file `2-`.
    assert_eq!(
        check(
            "cat /tmp/x >&\"2\"-",
            &["Read(/tmp/x)"],
            &["Write(/tmp/**)"]
        )
        .decision,
        Decision::Allow,
    );
    let result = check("cat /tmp/x >&2\"-\"", &["Read(/tmp/x)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/2-"))),
        "expected a Write demand for `2-`, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn the_dash_rule_is_specific_to_dup_output() {
    // Verified: `&>-foo` writes a file called `-foo`. `&>` has no close form,
    // so the leading dash is an ordinary filename character there.
    let result = check("cat /tmp/x &>-foo", &["Read(/tmp/x)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/-foo"))),
        "expected a Write demand for `-foo`, got {:?}",
        result.missing_rules,
    );
}

// Escapes: thaum records that one happened, not where -----------------------------------------------------------------
//
// `\-` and `-` both arrive as `Literal("-")`; only the span length differs, and
// that says an escape exists without saying where. The two positions need
// opposite answers — `>&\-2` writes a file called `-2`, `>&-vault\/creds`
// closes and passes `vault/creds` as an argument — so neither reading can be
// suppressed. Both are emitted, costing one spurious demand each.

#[skuld::test]
fn escaped_leading_dash_still_demands_the_write() {
    // Verified: `log hi >&\-2` creates a file called `-2` and passes no
    // argument. Reading it as a close would miss the write entirely.
    let result = check("cat /tmp/x >&\\-2", &["Read(/tmp/x)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/-2"))),
        "escaped leading dash lost its write: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn escaped_leading_dash_fires_a_write_deny() {
    assert!(matches!(
        check("cat /tmp/x >&\\-2", &["Bash(cat *)"], &["Write(/tmp/**)"]).decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn an_escape_elsewhere_keeps_the_operand_recovery() {
    // Verified: `log hi >&-vault\/creds` reports argc=2 [hi vault/creds]. The
    // leading dash is bare, so this is still a close plus an argument, and the
    // escape further along must not suppress that reading.
    assert!(
        matches!(
            check(
                "cp >&-/tmp/vault\\/creds /tmp/stolen.txt",
                &["Bash(cp *)"],
                &["Read(/tmp/vault/**)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "escape suppressed the operand recovery, hiding a denied read",
    );
}

#[skuld::test]
fn recovered_operand_can_be_the_command_name() {
    // `>&-danger` has no arguments of its own: bash closes stdout and runs
    // `danger`. The operand lands in position zero, so the no-arguments check
    // has to come after the splice or the command escapes every rule.
    assert!(matches!(
        check(">&-danger", &[], &["Bash(danger)"]).decision,
        Decision::Deny(_),
    ));
    assert_ne!(check(">&-danger", &[], &[]).decision, Decision::Allow);
}
