use super::helpers::strip_legacy_numeric;

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
    assert_eq!(
        strip_legacy_numeric(&["-"], false),
        vec!["-"],
    );
}

#[skuld::test]
fn strip_legacy_after_separator_unchanged() {
    assert_eq!(
        strip_legacy_numeric(&["--", "-30"], false),
        vec!["--", "-30"],
    );
}
