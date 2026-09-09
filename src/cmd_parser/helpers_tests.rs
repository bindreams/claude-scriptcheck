use super::helpers::{strip_legacy_numeric, strip_program_options};

#[skuld::test]
fn strip_legacy_dash_number() {
    assert_eq!(
        strip_legacy_numeric(&["-30", "file.txt"], false),
        vec!["file.txt"],
    );
}

#[skuld::test]
fn strip_legacy_dash_number_with_suffix() {
    assert_eq!(
        strip_legacy_numeric(&["-30b", "file.txt"], false),
        vec!["file.txt"],
    );
}

#[skuld::test]
fn strip_legacy_plus_number_allowed() {
    assert_eq!(
        strip_legacy_numeric(&["+30", "file.txt"], true),
        vec!["file.txt"],
    );
}

#[skuld::test]
fn strip_legacy_plus_number_disallowed() {
    assert_eq!(
        strip_legacy_numeric(&["+30", "file.txt"], false),
        vec!["+30", "file.txt"],
    );
}

#[skuld::test]
fn strip_legacy_normal_flags_unchanged() {
    assert_eq!(
        strip_legacy_numeric(&["-n", "5", "-v", "file.txt"], false),
        vec!["-n", "5", "-v", "file.txt"],
    );
}

#[skuld::test]
fn strip_legacy_bare_dash_unchanged() {
    assert_eq!(strip_legacy_numeric(&["-"], false), vec!["-"],);
}

#[skuld::test]
fn strip_legacy_after_separator_unchanged() {
    assert_eq!(
        strip_legacy_numeric(&["--", "-30"], false),
        vec!["--", "-30"],
    );
}

// Long-option abbreviations ===========================================================================================

#[skuld::test]
fn program_option_matches_exact_spelling() {
    let (rest, found) = strip_program_options(
        &["--use-compress-program=/tmp/x", "-cf", "a.tar"],
        &["use-compress-program"],
        &[],
    );
    assert!(found);
    assert_eq!(rest, vec!["-cf", "a.tar"]);
}

#[skuld::test]
fn program_option_matches_any_abbreviation() {
    // GNU getopt_long takes any unambiguous prefix; verified against GNU tar
    // 1.35, where `--use` alone still executes the program.
    for arg in [
        "--use-compress-prog=/tmp/x",
        "--use-compress=/tmp/x",
        "--use-comp=/tmp/x",
        "--use=/tmp/x",
    ] {
        let (_, found) =
            strip_program_options(&[arg, "-cf", "a.tar"], &["use-compress-program"], &[]);
        assert!(found, "{arg}");
    }
}

#[skuld::test]
fn program_option_consumes_a_separate_value() {
    let (rest, found) = strip_program_options(
        &["--to-comm", "/tmp/x", "-xf", "a.tar"],
        &["to-command"],
        &[],
    );
    assert!(found);
    assert_eq!(rest, vec!["-xf", "a.tar"]);
}

#[skuld::test]
fn exact_non_exec_option_wins_over_prefix() {
    // `--checkpoint` is a complete option of its own and a strict prefix of
    // `--checkpoint-action`; getopt_long resolves the exact match first.
    let (rest, found) = strip_program_options(
        &["--checkpoint=100", "-cf", "a.tar"],
        &["checkpoint-action"],
        &["checkpoint"],
    );
    assert!(!found);
    assert_eq!(rest, vec!["--checkpoint=100", "-cf", "a.tar"]);
}

#[skuld::test]
fn abbreviation_of_a_non_exec_option_still_matches_the_exec_one() {
    // `--checkpoint-a` is not the exact non-exec spelling, so the prefix rule
    // applies and it resolves to the exec option.
    let (_, found) = strip_program_options(
        &["--checkpoint-a=exec=sh"],
        &["checkpoint-action"],
        &["checkpoint"],
    );
    assert!(found);
}

#[skuld::test]
fn unrelated_long_options_are_left_alone() {
    let (rest, found) = strip_program_options(
        &["--verbose", "--directory=/tmp", "-xf", "a.tar"],
        &["use-compress-program", "to-command"],
        &[],
    );
    assert!(!found);
    assert_eq!(rest, vec!["--verbose", "--directory=/tmp", "-xf", "a.tar"]);
}

#[skuld::test]
fn bare_separator_is_not_an_option() {
    let (rest, found) =
        strip_program_options(&["--", "--use-comp"], &["use-compress-program"], &[]);
    assert!(!found);
    assert_eq!(rest, vec!["--", "--use-comp"]);
}
