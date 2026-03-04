use claude_scriptcheck::file_access::*;

#[skuld::test]
fn resolve_absolute() {
    assert_eq!(resolve_path("/usr/bin/ls", "/tmp"), "/usr/bin/ls");
}

#[skuld::test]
fn resolve_relative() {
    assert_eq!(resolve_path("foo/bar.txt", "/tmp"), "/tmp/foo/bar.txt");
}

#[skuld::test]
fn file_only_commands_recognized() {
    assert!(is_file_only_command("mkdir"));
    assert!(is_file_only_command("touch"));
    assert!(is_file_only_command("cat"));
    assert!(is_file_only_command("cp"));
    assert!(is_file_only_command("rm"));
    assert!(is_file_only_command("grep"));
    assert!(is_file_only_command("awk"));
    assert!(is_file_only_command("sed"));
}

#[skuld::test]
fn source_is_not_file_only() {
    assert!(!is_file_only_command("source"));
    assert!(!is_file_only_command("."));
}

#[skuld::test]
fn non_file_commands_not_file_only() {
    assert!(!is_file_only_command("echo"));
    assert!(!is_file_only_command("git"));
    assert!(!is_file_only_command("curl"));
}
