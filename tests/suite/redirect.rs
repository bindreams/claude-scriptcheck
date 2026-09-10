//! Redirect classification: what a redirect names, and what it hides.
//!
//! Covers `src/redirect.rs`. A redirect names a file, duplicates a descriptor,
//! or carries inline text. Getting that wrong in either direction is
//! expensive: a file read as a descriptor slips past every rule, and a
//! descriptor read as a file produces a deny no rule the user adds can lift.

use claude_scriptcheck::checker::Decision;
use pretty_assertions::assert_eq;

use crate::checker::{canonical, check};

#[path = "redirect/hook.rs"]
mod hook;

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

// Escapes: the source byte at the edge, not the parsed value ----------------------------------------------------------
//
// `-`, `\-` and `"-"` all parse to the same `Literal("-")`, so the decision
// comes from the source byte at the word's edge. That byte reproduces bash's
// asymmetry with no special case: escaping and quoting agree at the leading
// edge — `>&\-2` and `>&"-2"` both write a file called `-2` — and disagree at
// the trailing one, where `>&2\-` moves fd 2 and `>&2"-"` writes a file
// called `2-`.

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

#[skuld::test]
fn escaped_leading_dash_recovers_no_operand() {
    // The two readings are exclusive, and the escaped one wins here. Verified:
    // `p a >&\-vault/creds b` tries to *open* `-vault/creds` and passes `b` as
    // an ordinary argument — `vault/creds` is never read, so a `Read` deny
    // over it has nothing to fire on.
    assert_eq!(
        check(
            "cp >&\\-/tmp/vault/creds /tmp/stolen.txt",
            &["Bash(cp *)"],
            &["Read(/tmp/vault/**)"],
        )
        .decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn escape_after_the_edge_does_not_hide_the_write() {
    // Verified: `p hi >&\-2"suffix"` creates a file called `-2suffix` and
    // passes no argument. Deciding on the whole word — "does an escape appear
    // anywhere, and is every fragment a literal?" — read the quoted tail as
    // proof that no escape existed and dropped the write.
    let result = check("cat /tmp/x >&\\-2\"suffix\"", &["Read(/tmp/x)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/-2suffix"))),
        "expected a Write demand for `-2suffix`, got {:?}",
        result.missing_rules,
    );
    assert!(matches!(
        check(
            "cat /tmp/x >&\\-2\"suffix\"",
            &["Bash(cat *)"],
            &["Write(/tmp/**)"]
        )
        .decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn an_escaped_trailing_dash_still_moves_the_descriptor() {
    // The other half of the asymmetry: at the trailing edge an escape changes
    // nothing. Verified — `p hi >&2\-` moves fd 2 and creates no file, exactly
    // as `>&2-` does. Reading it as a filename would deny a valid command.
    assert_eq!(
        check("cat /tmp/x >&2\\-", &["Read(/tmp/x)"], &["Write(/tmp/**)"]).decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn an_escaped_operand_is_one_argument() {
    // Verified: `p a >&-vault\ creds` reports argc=2 [a "vault creds"] — the
    // escaped space is part of the operand, not a separator.
    assert!(matches!(
        check(
            "cp >&-/tmp/vault\\ creds /tmp/stolen.txt",
            &["Bash(cp *)"],
            &["Read(/tmp/vault creds)"],
        )
        .decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn an_escaped_operand_does_not_fabricate_a_write() {
    // The escape is inside the operand, so the leading dash is still bare and
    // nothing is opened. Verified: `p hi >&-my\ file.txt` creates no file.
    // Emitting a speculative write for `-/tmp/my file.txt` produced a `Deny`
    // — authoritative in every mode, and unliftable — on a command that only
    // writes its own destination.
    let result = check("cp >&-/tmp/my\\ file.txt /tmp/dst.txt", &[], &[]);
    assert!(
        !result.missing_rules.iter().any(|r| r.contains("/-/")),
        "fabricated an access for a file bash never opens: {:?}",
        result.missing_rules,
    );
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/my file.txt"))),
        "expected the operand to be read, got {:?}",
        result.missing_rules,
    );
}

// Operands that do not resolve statically -----------------------------------------------------------------------------
//
// A `>&-word` operand can be a glob or an expansion. Its value is then unknown,
// but its *position* is not, and position is what tells a source from a
// destination. Dropping the word instead of marking it unresolved shifts every
// later positional by one.

#[skuld::test]
fn a_dynamic_operand_holds_its_position() {
    // `grep <pattern> <file>` reads its second positional and skips its first.
    // Drop the operand and the deny-listed path slides into the pattern slot,
    // where nothing reads it. Verified: with `pat1` and `pat2` on disk, `p hi
    // >&-pat* zzz` reports argc=4 [hi pat1 pat2 zzz].
    for cmd in [
        "grep >&-$P /tmp/vault/creds",
        "grep >&-/tmp/pat* /tmp/vault/creds",
        "grep <&-$P /tmp/vault/creds",
        "grep >&-`id` /tmp/vault/creds",
    ] {
        assert!(
            matches!(
                check(cmd, &["Bash(grep *)"], &["Read(/tmp/vault/**)"]).decision,
                Decision::Deny(_),
            ),
            "a dropped operand shifted a denied path out of the file slot: {cmd}",
        );
    }
}

#[skuld::test]
fn a_dynamic_operand_is_visible_even_where_the_roles_agree() {
    // `cp <unknown> dst` and `cp dst` demand the same file rules, so the
    // splice shows up in the other demand it makes: an unresolved argument is
    // not static, and a command with one cannot skip its `Bash(...)` rule.
    let result = check("cp >&-$P /tmp/dst", &[], &[]);
    assert!(
        result.missing_rules.contains(&"Bash(cp)".to_string()),
        "the unresolved operand left no trace: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_empty_operand_is_still_an_argument() {
    // Verified: `p a >&-""` reports argc=2 [a ""]. The empty string occupies a
    // position like any other argument, so the path behind it stays in the
    // slot `grep` reads.
    assert!(matches!(
        check(
            "grep >&-\"\" /tmp/vault/creds",
            &["Bash(grep *)"],
            &["Read(/tmp/vault/**)"],
        )
        .decision,
        Decision::Deny(_),
    ));
}

// `<&-word` is the same splice as `>&-word` ---------------------------------------------------------------------------
//
// `closed_descriptor_operand` matches both, and so does bash: `p hi
// <&-vault/creds` reports argc=2 [hi vault/creds]. The read side is the more
// natural direction for exfiltration, so it is pinned rather than assumed.

#[skuld::test]
fn close_input_form_operand_becomes_an_argument() {
    let result = check("cat <&-/tmp/x", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/x"))),
        "expected a Read demand for the operand, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn close_input_form_operand_cannot_hide_a_denied_path() {
    assert!(matches!(
        check(
            "cat <&-/tmp/vault/creds",
            &["Bash(cat *)"],
            &["Read(/tmp/vault/**)"],
        )
        .decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn close_input_form_operand_keeps_its_source_position() {
    // `cp <&-vault/creds stolen.txt` reads the vault path and writes the other
    // one. Appending the operand instead of splicing it swaps the two.
    assert!(matches!(
        check(
            "cp <&-/tmp/vault/creds /tmp/stolen.txt",
            &["Bash(cp *)"],
            &["Read(/tmp/vault/**)"],
        )
        .decision,
        Decision::Deny(_),
    ));
    assert_eq!(
        check(
            "cp <&-/tmp/vault/creds /tmp/stolen.txt",
            &["Bash(cp *)"],
            &["Write(/tmp/vault/**)"],
        )
        .decision,
        Decision::Allow,
    );
}

#[skuld::test]
fn a_quoted_input_dash_form_names_nothing_at_all() {
    // Quoting or escaping the dash stops it terminating the token, and what is
    // left is not a descriptor. `<&word` takes only descriptor forms, so this
    // is an "ambiguous redirect" — verified for both spellings — which opens
    // no file and passes no argument.
    for cmd in ["cat <&\"-2\"", "cat <&\\-2"] {
        let result = check(cmd, &[], &[]);
        assert!(
            !result
                .missing_rules
                .iter()
                .any(|r| r.starts_with("Read(") || r.starts_with("Write(")),
            "an ambiguous redirect named a file: {cmd} -> {:?}",
            result.missing_rules,
        );
    }
}

// Redirects with no command word --------------------------------------------------------------------------------------
//
// `> log` truncates the file with nothing to run, and so does `FOO=x > log`.
// bash performs the redirections either way, so the accesses have to be
// checked even though there is no command name to hang a `Bash(...)` rule on.

#[skuld::test]
fn a_command_less_redirect_still_writes() {
    let result = check("> /tmp/vault/creds", &[], &[]);
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/creds"))),
        "expected a Write demand, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_command_less_redirect_fires_a_write_deny() {
    for cmd in [
        "> /tmp/vault/creds",
        ">> /tmp/vault/creds",
        ">| /tmp/vault/creds",
        ">& /tmp/vault/creds",
        "&> /tmp/vault/creds",
        "<> /tmp/vault/creds",
        "FOO=x > /tmp/vault/creds",
    ] {
        assert!(
            matches!(
                check(cmd, &[], &["Write(/tmp/vault/**)"]).decision,
                Decision::Deny(_),
            ),
            "command-less redirect escaped its deny rule: {cmd}",
        );
    }
}

#[skuld::test]
fn a_command_less_redirect_fires_a_read_deny() {
    for cmd in ["< /tmp/vault/creds", "<> /tmp/vault/creds"] {
        assert!(
            matches!(
                check(cmd, &[], &["Read(/tmp/vault/**)"]).decision,
                Decision::Deny(_),
            ),
            "command-less redirect escaped its deny rule: {cmd}",
        );
    }
}

#[skuld::test]
fn a_command_less_redirect_cannot_be_suppressed_by_a_bash_rule() {
    // There is no command name, so no `Bash(...)` rule describes this — and a
    // rule that matched nothing must not suppress the write demand either.
    let result = check("> /tmp/vault/creds", &["Bash(cat *)", "Bash(*)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/creds"))),
        "a Bash rule suppressed a command-less redirect: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_assignment_without_a_redirect_needs_nothing() {
    assert_eq!(check("FOO=bar", &[], &[]).decision, Decision::Allow);
}

#[skuld::test]
fn eval_still_performs_its_redirects() {
    // `eval` cannot be analyzed, so it asks — but its redirect is not part of
    // the code being evaluated. bash truncates the file before eval runs.
    let result = check("eval x > /tmp/vault/creds", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/creds"))),
        "expected a Write demand, got {:?}",
        result.missing_rules,
    );
    // And the deny fires even where a `Bash(eval *)` allow rule has already
    // waved the eval itself through — file denies are never suppressed.
    for allow in [&[] as &[&str], &["Bash(eval *)"]] {
        assert!(
            matches!(
                check(
                    "eval x > /tmp/vault/creds",
                    allow,
                    &["Write(/tmp/vault/**)"]
                )
                .decision,
                Decision::Deny(_),
            ),
            "eval carried its redirect past the file rules ({allow:?})",
        );
    }
}

#[skuld::test]
fn a_bash_allow_rule_suppresses_a_redirect_demand_but_not_a_deny() {
    // The documented suppression contract, checked on the paths that return
    // early: a matching Bash allow rule silences the missing-rule demand, and a
    // Deny still fires.
    let result = check("eval x > /tmp/out", &["Bash(eval *)"], &[]);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "{:?}",
        result.missing_rules
    );
}
