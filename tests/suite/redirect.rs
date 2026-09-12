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
fn a_bash_allow_rule_suppresses_an_evals_redirect_demand() {
    // The documented suppression contract on a path that returns early: a
    // matching Bash allow rule silences the missing-rule demand. The deny half
    // is `eval_still_performs_its_redirects`, which runs the same command with
    // the same allow rule and a deny rule in force.
    let result = check("eval x > /tmp/out", &["Bash(eval *)"], &[]);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "{:?}",
        result.missing_rules
    );
}

// Words and shapes that name no file ----------------------------------------------------------------------------------
//
// Each of these opens nothing in bash, so recording an access would be a demand
// — or a `Deny` — on a file the command never touches.

#[skuld::test]
fn an_empty_target_names_no_file() {
    // Verified: `cat /etc/hosts > ""` reports "No such file or directory" and
    // creates nothing. Resolving the empty path instead names the working
    // directory, which a `Deny(Write(...))` over the project would then block.
    for cmd in [
        "cat /tmp/in > \"\"",
        "cat /tmp/in >> ''",
        "cat /tmp/in >| \"\"",
        "cat /tmp/in < \"\"",
        "cat /tmp/in <> \"\"",
        "cat /tmp/in >& \"\"",
        "cat /tmp/in &> \"\"",
        "> \"\"",
    ] {
        let result = check(cmd, &[], &[]);
        let from_the_redirect: Vec<&String> = result
            .missing_rules
            .iter()
            .filter(|r| {
                (r.starts_with("Read(") || r.starts_with("Write("))
                    && !r.ends_with(&format!("{})", canonical("/tmp/in")))
            })
            .collect();
        assert!(
            from_the_redirect.is_empty(),
            "an empty target named a file: {cmd} -> {from_the_redirect:?}",
        );
    }
}

#[skuld::test]
fn an_empty_target_does_not_deny_the_working_directory() {
    // The specific failure the guard prevents: a deny over the directory the
    // command runs in, fired by a redirect that opens nothing.
    for cmd in ["cat /tmp/in > \"\"", "cat /tmp/in <> \"\"", "> \"\""] {
        assert!(
            !matches!(
                check(cmd, &["Bash(cat *)"], &["Write(/tmp/**)"]).decision,
                Decision::Deny(_),
            ),
            "an empty target denied the working directory: {cmd}",
        );
    }
}

// Redirects on a compound command -------------------------------------------------------------------------------------
//
// `{ ...; } > log` is not attached to any one command, so it is walked by
// `visit_redirect` rather than by `check_command`, and no `Bash(...)` rule can
// suppress it. The classification is the same; the route to it is not.

#[skuld::test]
fn a_compound_redirect_is_classified_the_same_way() {
    for cmd in [
        "{ cat /tmp/x; } <> /tmp/y",
        "while read l; do echo; done <> /tmp/y",
        "if true; then echo; fi <> /tmp/y",
    ] {
        let result = check(cmd, &[], &[]);
        for demand in [
            format!("Read({})", canonical("/tmp/y")),
            format!("Write({})", canonical("/tmp/y")),
        ] {
            assert!(
                result.missing_rules.contains(&demand),
                "compound `<>` lost {demand}: {cmd} -> {:?}",
                result.missing_rules,
            );
        }
    }
}

#[skuld::test]
fn a_compound_redirect_fires_both_denies() {
    for rule in ["Read(/tmp/vault/**)", "Write(/tmp/vault/**)"] {
        assert!(
            matches!(
                check("{ cat; } <> /tmp/vault/creds", &["Bash(cat *)"], &[rule]).decision,
                Decision::Deny(_),
            ),
            "compound `<>` escaped {rule}",
        );
    }
}

#[skuld::test]
fn a_compound_redirect_is_not_suppressed_by_a_bash_rule() {
    // The redirect belongs to the group, not to `cat`, so a rule naming `cat`
    // has not consented to it.
    let result = check("{ cat /tmp/x; } > /tmp/y", &["Bash(cat *)"], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/y"))),
        "a Bash rule suppressed a compound redirect: {:?}",
        result.missing_rules,
    );
}

// What kind of word bash reads the recovered operand as ---------------------------------------------------------------
//
// `>&-` ends the redirect token, so what follows starts a fresh word — and
// bash decides what kind of word it is from the spelling, before expansion.
// The parser never saw a word boundary there, so these rules have to be
// applied where the operand is recovered.

#[skuld::test]
fn an_assignment_shaped_operand_is_not_the_command_name() {
    // Verified: `>&-FOO=1 p x` reports `argc=1 [x]` with `FOO=1` in the
    // environment. Reading `FOO=1` as the command name leaves every
    // `Bash(rm ...)` rule looking at a name no rule can match.
    for cmd in [
        ">&-FOO=1 rm -rf /tmp/zzz",
        ">&-FOO+=1 rm -rf /tmp/zzz",
        ">&-FOO=1 >&-BAR=2 rm -rf /tmp/zzz",
    ] {
        assert!(
            matches!(check(cmd, &[], &["Bash(rm *)"]).decision, Decision::Deny(_),),
            "an assignment-shaped operand hid the command name: {cmd}",
        );
    }
}

#[skuld::test]
fn an_assignment_shaped_operand_after_the_command_name_is_an_argument() {
    // Verified: `p a >&-FOO=1` reports `argc=2 [a] [FOO=1]` and leaves `FOO`
    // unset. Past the command word, the assignment rule no longer applies.
    let result = check("cat /tmp/in >&-FOO=1", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/FOO=1"))),
        "expected the operand to be an argument, got {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_invalid_name_is_a_command_word_not_an_assignment() {
    // Verified: `>&-1FOO=1 p x` is a `command not found` for `1FOO=1` — a name
    // cannot start with a digit, so the word is an ordinary one.
    let result = check(">&-1FOO=1 x", &[], &[]);
    assert!(
        result.missing_rules.iter().any(|r| r.contains("1FOO=1")),
        "an invalid name was swallowed as an assignment: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_operand_starting_a_comment_ends_the_command() {
    // Verified: `p in >&-#foo bar` reports `argc=1 [in]`. Both `#foo` and the
    // word after it are comment text, so demanding a read on either is a
    // demand — or a deny — on a file the command never opens.
    let result = check("cat /tmp/in >&-#foo /tmp/vault/creds", &[], &[]);
    assert_eq!(
        result.missing_rules,
        vec![format!("Read({})", canonical("/tmp/in"))],
        "a comment was read as arguments",
    );
    assert!(
        !matches!(
            check(
                "cat /tmp/in >&-#foo /tmp/vault/creds",
                &["Bash(cat *)"],
                &["Read(/tmp/vault/**)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "a commented-out path fired a deny",
    );
}

// Nested commands carry their own source ------------------------------------------------------------------------------
//
// thaum parses a substitution's body separately, so spans inside `$(...)`,
// `` `...` `` and `<(...)` restart at zero. Reading the outer command's text at
// those offsets lands in another command's bytes — a wrong answer rather than a
// missing one, which is why the source is re-based when the walk descends.

#[skuld::test]
fn a_redirect_inside_a_substitution_is_classified_against_its_own_source() {
    // The operand is a real read wherever it appears. Padding shifts the outer
    // offsets so a stale source reads a different byte for every case.
    for cmd in [
        "echo $(cat >&-/tmp/vault/creds)",
        "echo aaaaaaaaaaaaaaaaaaaa $(cat >&-/tmp/vault/creds)",
        "echo \"$(cat >&-/tmp/vault/creds)\"",
        "echo `cat >&-/tmp/vault/creds`",
        "diff <(cat >&-/tmp/vault/creds) /tmp/b",
        "echo $(echo $(cat >&-/tmp/vault/creds))",
    ] {
        assert!(
            matches!(
                check(
                    cmd,
                    &["Bash(echo *)", "Bash(cat *)", "Bash(diff *)"],
                    &["Read(/tmp/vault/**)"]
                )
                .decision,
                Decision::Deny(_),
            ),
            "a denied read hid inside a substitution: {cmd}",
        );
    }
}

#[skuld::test]
fn a_substitution_does_not_fabricate_a_write_from_the_outer_source() {
    // Reading the outer text at inner offsets also invents file accesses. The
    // operand here is an argument, not a target, so nothing is written.
    let result = check("echo aaaaaaaaaaaaaaaa $(cat >&-/tmp/in)", &[], &[]);
    assert!(
        !result.missing_rules.iter().any(|r| r.starts_with("Write(")),
        "a stale source invented a write: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_unlocatable_substitution_body_still_misses_nothing() {
    // `pre$(cmd)post` holds the substitution in part of a word, and locating
    // the body there would mean re-deriving where each fragment started. The
    // source is unknown instead, and an unknown source over-approximates: the
    // operand is recovered even though the dash cannot be confirmed bare.
    assert!(
        matches!(
            check(
                "echo pre$(cat >&-/tmp/vault/creds)post",
                &["Bash(echo *)", "Bash(cat *)"],
                &["Read(/tmp/vault/**)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "a denied read hid in a partly-substituted word",
    );
}

// Words the parser sorted before it knew where the command name was ---------------------------------------------------

#[skuld::test]
fn an_assignment_after_a_recovered_command_name_is_an_argument() {
    // Verified: `>&-env FOO=1 p x` runs `env` with `FOO=1` as an argument —
    // env reports `p: No such file or directory`, so it consumed `FOO=1`
    // itself. The parser sorted `FOO=1` into the assignments because it never
    // saw `env`, and dropping it there shifts every later argument left.
    let result = check(">&-env FOO=1 cat /tmp/in", &[], &[]);
    assert_eq!(
        result.missing_rules,
        vec!["Bash(env FOO=1 cat /tmp/in)".to_string()],
        "a word the parser sorted as an assignment went missing",
    );
}

#[skuld::test]
fn a_subscripted_name_is_still_an_assignment() {
    // Verified: `>&-a[0]=1 p x` runs `p`, so `a[0]=1` is a prefix assignment
    // and not the command name. `[0]` also makes the word a glob, so reading it
    // as the command name produces a *dynamic* name — which a deny rule happens
    // to catch anyway. The rule the command demands is what tells them apart.
    // `rm` is file-only, so recognising it as the command name is what turns
    // the demand into a path rule instead of one for a command name nobody can
    // write.
    let result = check(">&-a[0]=1 rm -rf /tmp/zzz", &[], &[]);
    assert_eq!(
        result.missing_rules,
        vec![format!("Write({}/**)", canonical("/tmp/zzz"))],
        "an array-element assignment was read as the command name",
    );
    assert!(matches!(
        check(">&-a[0]=1 rm -rf /tmp/zzz", &[], &["Bash(rm *)"]).decision,
        Decision::Deny(_),
    ));
}

#[skuld::test]
fn a_comment_ends_the_line_for_redirects_too() {
    // Verified: `p in >&-#foo > evil` reports `argc=1 [in]` and creates no
    // `evil`. A comment runs to the end of the line, so the redirects after it
    // are never performed either.
    let result = check("cat /tmp/in >&-#foo > /tmp/vault/creds", &[], &[]);
    assert_eq!(
        result.missing_rules,
        vec![format!("Read({})", canonical("/tmp/in"))],
        "a redirect after a comment was performed",
    );
    assert!(
        !matches!(
            check(
                "cat /tmp/in >&-#foo > /tmp/vault/creds",
                &["Bash(cat *)"],
                &["Write(/tmp/vault/**)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "a commented-out redirect fired a deny",
    );
}

// One substitution's source is not another's --------------------------------------------------------------------------
//
// A word can hold more than one substitution, and `$(a)$(b)` starts with `$(`
// and ends with `)` exactly as `$(cmd)` does. Deciding from the text would
// strip it to `a)$(b` — a source that is wrong rather than absent, which is the
// one outcome worse than not knowing.

#[skuld::test]
fn a_second_substitution_does_not_borrow_the_first_ones_source() {
    // Whether a stolen source gives the wrong answer depends on what byte the
    // shifted offset lands on, so one spelling pins nothing: the padding is
    // swept instead. Every length must classify the write, and the first
    // substitution ends in `-` so a stolen byte reads as a descriptor dash.
    for pad in 0..24 {
        let filler = "x".repeat(pad);
        let cmd = format!("echo $({filler}-)$(cat >&vault/creds)");
        let result = check(&cmd, &[], &[]);
        assert!(
            result
                .missing_rules
                .contains(&format!("Write({})", canonical("/tmp/vault/creds"))),
            "a write escaped through a second substitution at padding {pad}: {:?}",
            result.missing_rules,
        );
        assert!(
            matches!(
                check(
                    &cmd,
                    &["Bash(echo *)", "Bash(cat *)", "Bash(*)"],
                    &["Write(/tmp/vault/**)"],
                )
                .decision,
                Decision::Deny(_),
            ),
            "a deny rule missed the write at padding {pad}",
        );
    }
}

#[skuld::test]
fn the_trailing_edge_is_decided_without_the_source() {
    // Inside a word holding two substitutions the source is unknown, and the
    // trailing-dash rule still has to be right — escaping does not change it,
    // quoting does, and a fragment's kind says which happened. `$(:)` is a
    // no-op that makes the enclosing word unlocatable.
    for (cmd, writes) in [
        ("echo $(:)$(cat /tmp/x >&2-)", false),
        ("echo $(:)$(cat /tmp/x >&\"2\"-)", false),
        ("echo $(:)$(cat /tmp/x >&2\\-)", false),
        ("echo $(:)$(cat /tmp/x >&2\"-\")", true),
    ] {
        let result = check(cmd, &[], &[]);
        let wrote = result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/2-")));
        assert_eq!(wrote, writes, "{cmd} -> {:?}", result.missing_rules);
    }
}

#[skuld::test]
fn an_unlocatable_body_keeps_an_unresolved_operand_in_place() {
    // `cp <unknown> vault/creds` writes the vault path and `cp vault/creds`
    // only reads it. With no source to confirm the dash is bare, the operand is
    // recovered anyway — dropping it would move the denied path into the other
    // slot.
    let result = check("echo pre$(cp /tmp/vault/creds >&-$P)post", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "an unresolved operand was dropped, inverting the read: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_unlocatable_body_still_recognises_an_assignment() {
    // Without the source the spelling is unavailable, and the value is the
    // closest thing to it. Reading `FOO=1` as the command name would leave
    // `cat`'s own arguments unparsed, so the read never reaches the rules.
    let result = check("echo pre$(>&-FOO=1 cat /tmp/vault/creds)post", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "an assignment was read as the command name: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_comment_ends_the_line_not_just_the_command() {
    // Verified: `cat /etc/hosts >&-#foo | rm -rf zzz` leaves `zzz` in place —
    // the `rm` is comment text. Demanding its write is a deny no rule lifts,
    // on a command bash never runs.
    for cmd in [
        "cat /tmp/in >&-#foo | rm -rf /tmp/zzz",
        "cat /tmp/in >&-#foo; rm -rf /tmp/zzz",
        "cat /tmp/in >&-#foo && rm -rf /tmp/zzz",
    ] {
        let result = check(cmd, &[], &[]);
        assert_eq!(
            result.missing_rules,
            vec![format!("Read({})", canonical("/tmp/in"))],
            "a commented-out command was still demanded: {cmd}",
        );
        assert!(
            !matches!(
                check(cmd, &["Bash(cat *)"], &["Write(/tmp/**)"]).decision,
                Decision::Deny(_),
            ),
            "a commented-out command fired a deny: {cmd}",
        );
    }
}

#[skuld::test]
fn a_comment_inside_a_substitution_ends_only_its_own_line() {
    // The scoping control. The comment is inside `$(...)`, so the `rm` after
    // the substitution is a real command and must still be demanded.
    let result = check("echo $(cat /tmp/in >&-#foo) ; rm -rf /tmp/zzz", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({}/**)", canonical("/tmp/zzz"))),
        "a comment inside a substitution silenced the line outside it: {:?}",
        result.missing_rules,
    );
}

// Sources that are not the bytes they came from -----------------------------------------------------------------------

#[skuld::test]
fn a_backtick_substitution_is_never_sliced_for_its_body() {
    // bash resolves `\$`, `` \` `` and `\\` inside backticks *before* parsing,
    // so the body that was parsed is shorter than the text between them and
    // every span inside it is shifted. Verified: bash writes `vault/creds`
    // here, and slicing anyway classified it as a read — the write escaped
    // every rule.
    let result = check("echo `cat \\$\\$\\$\\$- >&vault/creds`", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/creds"))),
        "a write escaped through a backtick substitution: {:?}",
        result.missing_rules,
    );
    assert!(
        matches!(
            check(
                "echo `cat \\$\\$\\$\\$- >&vault/creds`",
                &["Bash(echo *)", "Bash(cat *)"],
                &["Write(/tmp/vault/**)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "a deny rule missed a write inside backticks",
    );
}

#[skuld::test]
fn an_assignment_value_still_locates_its_substitution() {
    // An assignment's value word spans the whole `name=value`, so the name has
    // to come off before the `$(` shows. Without that the body is unlocatable
    // and the redirect is scored twice — the write below is the spurious half.
    let result = check("V=$(cat /tmp/in >&-/tmp/vault/creds)", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "the operand was lost: {:?}",
        result.missing_rules,
    );
    assert!(
        !result.missing_rules.iter().any(|r| r.starts_with("Write(")),
        "an unlocated body fabricated a write: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_comment_stops_at_the_newline() {
    // Verified: `cat in >&-#foo` followed by `echo PWNED > secret.txt` on the
    // next line writes `secret.txt`. A comment ends the *line*, so silencing
    // everything after it silences ordinary code — and silence here is an
    // access that reaches no rule at all.
    let cmd = "cat /tmp/in >&-#foo\necho BOO > /tmp/vault/pwned";
    let result = check(cmd, &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/pwned"))),
        "the line after a comment was silenced: {:?}",
        result.missing_rules,
    );
    assert!(
        matches!(
            check(
                cmd,
                &["Bash(cat *)", "Bash(echo *)"],
                &["Write(/tmp/vault/**)"]
            )
            .decision,
            Decision::Deny(_),
        ),
        "a deny rule missed a write on the line after a comment",
    );
}

#[skuld::test]
fn a_comment_silences_the_arguments_after_it() {
    // The same line, the other direction: words after the comment are comment
    // text, substitutions included, so `$(rm -rf vault)` never runs.
    let result = check("cat /tmp/in >&-#foo $(rm -rf /tmp/vault)", &[], &[]);
    assert_eq!(
        result.missing_rules,
        vec![format!("Read({})", canonical("/tmp/in"))],
        "a commented-out substitution was still walked",
    );
}

#[skuld::test]
fn a_line_continuation_does_not_hide_the_leading_dash() {
    // bash removes `\<newline>` before tokenising, so a word can begin a
    // continuation into its own span. Verified: with the dash on the next line
    // `p a >&\<newline>-vault/creds b` reports `argc=3 [a vault/creds b]` and
    // creates no file — reading the span's first byte finds the backslash,
    // invents a write, and drops the operand carrying the real read.
    for cmd in [
        "cat a >&\\\n-/tmp/vault/creds b",
        "cat a >&\\\n\\\n-/tmp/vault/creds b",
    ] {
        let result = check(cmd, &[], &[]);
        assert!(
            result
                .missing_rules
                .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
            "a continuation hid the operand: {cmd:?} -> {:?}",
            result.missing_rules,
        );
        assert!(
            !result.missing_rules.iter().any(|r| r.contains("/-/")),
            "a continuation fabricated a write: {cmd:?} -> {:?}",
            result.missing_rules,
        );
        assert!(
            matches!(
                check(cmd, &["Bash(cat *)"], &["Read(/tmp/vault/**)"]).decision,
                Decision::Deny(_),
            ),
            "a deny rule missed a read hidden by a continuation: {cmd:?}",
        );
    }
}

#[skuld::test]
fn a_quoted_assignment_value_still_locates_its_substitution() {
    // `v="$(cmd)"` wears both a name and quotes, and the name has to come off
    // first. Otherwise the body is unlocatable and the redirect is scored
    // twice — the fabricated half being a write to `-<path>`.
    let result = check("V=\"$(cat /tmp/in >&-/tmp/vault/creds)\"", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "the operand was lost: {:?}",
        result.missing_rules,
    );
    assert!(
        !result.missing_rules.iter().any(|r| r.starts_with("Write(")),
        "an unlocated body fabricated a write: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_continuation_inside_the_operand_does_not_hide_an_assignment() {
    // bash removes `\<newline>` before deciding what kind of word this is, and
    // one can split a name. Verified: `>&-FOO\<newline>=1 p x` reports
    // `argc=1 [x] FOO=1`, so `FOO=1` is a prefix assignment and `p` the
    // command. Leaving the continuation in makes `FOO` an invalid name, and
    // then the whole word becomes the command that no `Bash(rm ...)` rule
    // describes.
    for cmd in [
        ">&\\\n-FOO=1 rm -rf /tmp/zzz",
        ">&-FOO\\\n=1 rm -rf /tmp/zzz",
        ">&-\\\nFOO=1 rm -rf /tmp/zzz",
        ">&-F\\\nOO=1 rm -rf /tmp/zzz",
    ] {
        let result = check(cmd, &[], &[]);
        assert_eq!(
            result.missing_rules,
            vec![format!("Write({}/**)", canonical("/tmp/zzz"))],
            "a continuation hid the command name: {cmd:?}",
        );
        assert!(
            matches!(check(cmd, &[], &["Bash(rm *)"]).decision, Decision::Deny(_)),
            "a deny rule missed the command behind a continuation: {cmd:?}",
        );
    }
}

#[skuld::test]
fn a_substitution_inside_a_recovered_operand_is_walked() {
    // The operand is an argument, and an argument's interior is walked:
    // `cat >&-$(rm -rf vault)` runs the `rm`. Leaving it unwalked put a command
    // substitution somewhere no rule could see it.
    for cmd in [
        "cat /tmp/in >&-$(rm -rf /tmp/vault)",
        "cat /tmp/in <&-$(rm -rf /tmp/vault)",
        "cat /tmp/in >&-`rm -rf /tmp/vault`",
    ] {
        assert!(
            matches!(check(cmd, &[], &["Bash(rm *)"]).decision, Decision::Deny(_)),
            "a substitution hid inside a recovered operand: {cmd}",
        );
    }
    // The control: commented out, so bash runs none of it.
    assert!(
        !matches!(
            check(
                "cat /tmp/in >&-#foo $(rm -rf /tmp/vault)",
                &[],
                &["Bash(rm *)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "a commented-out substitution was walked anyway",
    );
}

#[skuld::test]
fn a_redirect_on_the_line_after_a_comment_survives() {
    // A guard rather than a regression test: the redirect filter and the
    // command filter derive their answer from one shared range now, where they
    // once each computed an end. No spelling was found where the two disagreed,
    // so this pins the property rather than a defect.
    let cmd = "cat /tmp/in >&-#foo\ncat /tmp/in2 > /tmp/vault/pwned";
    let result = check(cmd, &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/pwned"))),
        "a redirect on the next line was silenced: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_comment_silences_an_assignment_value_on_the_same_line() {
    // `>&-#foo V=$(rm -rf vault)` is a comment from `#` onwards, so the
    // assignment never runs — its value must not be walked either.
    assert!(
        !matches!(
            check(">&-#foo V=$(rm -rf /tmp/vault)", &[], &["Bash(rm *)"]).decision,
            Decision::Deny(_),
        ),
        "a commented-out assignment value was walked",
    );
}

#[skuld::test]
fn a_continuation_does_not_drag_the_next_line_into_a_comment() {
    // A node's span can start on a line continuation, which belongs to neither
    // line. Verified: this script creates `vault/pwned` — the comment ends at
    // the newline and the redirect is on the line after it, so comparing the
    // span's raw start against the comment's range silenced a write bash
    // performs.
    let cmd = "cat /tmp/in >&-#foo\\\n> /tmp/vault/pwned";
    let result = check(cmd, &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Write({})", canonical("/tmp/vault/pwned"))),
        "a continuation dragged the next line into the comment: {:?}",
        result.missing_rules,
    );
    assert!(
        matches!(
            check(cmd, &["Bash(cat *)"], &["Write(/tmp/vault/**)"]).decision,
            Decision::Deny(_),
        ),
        "a deny rule missed a write on the line after a continued comment",
    );
}

#[skuld::test]
fn the_operand_that_starts_a_comment_is_not_walked() {
    // `cat in >&-#$(rm -rf x)` is a comment from the `#`, so the substitution
    // inside it never runs. Walking it anyway demands a write — and under a
    // directory-wide deny, blocks a command that does nothing.
    let result = check("cat /tmp/in >&-#$(rm -rf /tmp/zzz)", &[], &[]);
    assert_eq!(
        result.missing_rules,
        vec![format!("Read({})", canonical("/tmp/in"))],
        "a substitution inside a comment was walked",
    );
    assert!(
        !matches!(
            check(
                "cat /tmp/in >&-#$(rm -rf /tmp/zzz)",
                &["Bash(cat *)"],
                &["Write(/tmp/**)"],
            )
            .decision,
            Decision::Deny(_),
        ),
        "a commented-out substitution fired a deny",
    );
    // The control: uncommented, the same substitution must still be walked.
    assert!(
        matches!(
            check("cat /tmp/in >&-$(rm -rf /tmp/zzz)", &[], &["Bash(rm *)"]).decision,
            Decision::Deny(_),
        ),
        "the control stopped working: an uncommented operand substitution is unwalked",
    );
}

#[skuld::test]
fn a_word_that_cannot_begin_with_a_bare_dash_is_ruled_out() {
    // With no source to read, the fragment kinds still settle it: only a
    // literal can hold a bare dash, so a quoted, parameter or substitution
    // fragment at the front means this is not the close form. `$(:)$(...)`
    // makes the body unlocatable, which is what removes the source.
    for (cmd, recovers) in [
        ("echo $(:)$(cat >&-/tmp/vault/creds)", true),
        ("echo $(:)$(cat >&\"-\"/tmp/vault/creds)", false),
        ("echo $(:)$(cat >&$X/tmp/vault/creds)", false),
    ] {
        let denied = matches!(
            check(
                cmd,
                &["Bash(echo *)", "Bash(cat *)"],
                &["Read(/tmp/vault/**)"]
            )
            .decision,
            Decision::Deny(_),
        );
        assert_eq!(denied, recovers, "{cmd}");
    }
}

#[skuld::test]
fn a_backslash_in_a_comment_does_not_continue_it() {
    // A backslash inside a comment is comment text, not a line continuation:
    // the comment still ends at the newline and the next line runs. Verified —
    // a script whose commented line ends in `\` still prints the next line's
    // output. thaum has no comment model, so it joins the two lines into one
    // word, and every consumer of the comment range has to test *containment*
    // rather than "is it after the comment started".
    for cmd in [
        "cat /tmp/in >&-#c\\\ncat /tmp/vault/creds",
        "cat /tmp/in >&-#c\\\ncat /tmp/vault/creds | cat",
        "cat /tmp/in >&-#c\\\ncat >&-/tmp/vault/creds",
    ] {
        let result = check(cmd, &[], &[]);
        assert!(
            result
                .missing_rules
                .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
            "the line after a commented continuation was silenced: {cmd:?} -> {:?}",
            result.missing_rules,
        );
        assert!(
            matches!(
                check(cmd, &["Bash(cat *)"], &["Read(/tmp/vault/**)"]).decision,
                Decision::Deny(_),
            ),
            "a deny rule missed a read after a commented continuation: {cmd:?}",
        );
    }
}

#[skuld::test]
fn a_commented_assignment_does_not_demand_a_bash_rule() {
    // `ls >&-#c FOO=1` runs plain `ls`: the assignment is comment text, so it
    // sets nothing and cannot make the command non-file-only. Demanding a
    // `Bash(ls)` rule for it is a prompt on a command that does nothing
    // unusual, and under `dontAsk` a deny.
    let result = check("ls /tmp/x >&-#c FOO=1", &[], &[]);
    assert!(
        !result.missing_rules.iter().any(|r| r.starts_with("Bash(")),
        "a commented-out assignment forced a Bash rule: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_operand_after_the_comments_newline_is_still_recovered() {
    // The operand filter tests containment, not "after the comment started".
    // A second redirect on the next line carries a real argument, and bash
    // runs it — silencing it loses the read entirely.
    let cmd = "cat /tmp/in >&-#c\\\ncat >&-/tmp/vault/creds";
    let result = check(cmd, &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "an operand past the comment's newline was dropped: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn an_unknown_source_does_not_assume_an_assignment() {
    // With no source the operand's spelling is unavailable and its *value*
    // stands in. Treating every such operand as an assignment would drop it
    // from the argument list, and a dropped operand takes its access with it.
    let result = check("echo $(:)$(cat >&-/tmp/vault/creds)", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "an unresolved operand was assumed to be an assignment: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_compound_redirect_inside_a_comment_is_not_performed() {
    // `visit_redirect` walks redirects that belong to a group rather than a
    // command. One sitting inside a comment is comment text like any other.
    let result = check("{ cat /tmp/in; } >&-#c > /tmp/vault/pwned", &[], &[]);
    assert!(
        !result
            .missing_rules
            .iter()
            .any(|r| r.contains(&canonical("/tmp/vault/pwned"))),
        "a commented-out compound redirect was performed: {:?}",
        result.missing_rules,
    );
}

#[skuld::test]
fn a_comment_does_not_escape_its_substitution() {
    // The range is restored when the walk leaves a substitution body. If it
    // leaked, the command after the substitution would be silenced — and a
    // silenced command reaches no rule at all.
    let result = check("echo $(cat /tmp/in >&-#c) ; cat /tmp/vault/creds", &[], &[]);
    assert!(
        result
            .missing_rules
            .contains(&format!("Read({})", canonical("/tmp/vault/creds"))),
        "a comment leaked out of its substitution: {:?}",
        result.missing_rules,
    );
}
