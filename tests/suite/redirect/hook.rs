//! Redirect classification, end to end through the hook binary.
//!
//! The library-level cases live in the parent module; these run the compiled
//! binary against a settings file, so they also pin the pieces the library
//! tests cannot see: settings loading, the project root, and the verdict the
//! agent actually receives.
//!
//! Most tests here carry a `Bash(...)` allow rule deliberately. A Bash allow
//! rule suppresses secondary demands, so a deny firing anyway is the property
//! each bypass defeated.

use crate::integration::{run_bash_hook, vault_paths, write_vault_project};

#[skuld::test]
fn hook_dup_output_to_file_denies(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `>&FILE` with no leading fd redirects stdout and stderr to that file.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cat *)"],"deny":["Write(//{abs}/vault/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(
            &format!("cat {}/vault/creds >& {}/vault/x", p.root, p.root),
            &p.root,
        ),
        "deny",
    );
}

#[skuld::test]
fn hook_read_write_redirect_denies_on_read_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `<>` opens for reading as well as writing, so a Read deny must fire.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cat *)"],"deny":["Read(//{abs}/vault/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(&format!("cat <> {}/vault/creds", p.root), &p.root),
        "deny",
    );
}

#[skuld::test]
fn hook_read_write_redirect_denies_on_write_rule(#[fixture(temp_dir)] dir: &std::path::Path) {
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cat *)"],"deny":["Write(//{abs}/vault/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(&format!("cat <> {}/vault/creds", p.root), &p.root),
        "deny",
    );
}

#[skuld::test]
fn hook_descriptor_forms_are_not_file_targets(#[fixture(temp_dir)] dir: &std::path::Path) {
    // No Bash allow rule here: with one, suppression would hide an over-eager
    // file access and the control would pass vacuously.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Read(//{abs}/vault/creds)"]}}"#),
    );
    for suffix in ["2>&1", ">&2", ">&-", ">&2-", ">&1-", "<&0-", "<<< hi"] {
        assert_eq!(
            run_bash_hook(&format!("cat {}/vault/creds {suffix}", p.root), &p.root),
            "allow",
            "{suffix}",
        );
    }
}

#[skuld::test]
fn hook_descriptor_move_does_not_trigger_a_write_deny(#[fixture(temp_dir)] dir: &std::path::Path) {
    // A deny no rule can lift is the worst outcome available, so the move form
    // must not be read as a file called `2-`.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Read(//{abs}/vault/creds)"],"deny":["Write(//{abs}/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(&format!("cat {}/vault/creds >&2-", p.root), &p.root),
        "allow",
    );
}

#[skuld::test]
fn hook_fd_one_dup_output_to_file_denies(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `1>&f` and its zero-padded spellings redirect to a file just as `>&f`
    // does; only a descriptor other than 1 is an ambiguous-redirect error.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cat *)"],"deny":["Write(//{abs}/vault/**)"]}}"#),
    );
    for fd in ["1", "01", "001"] {
        assert_eq!(
            run_bash_hook(
                &format!("cat {}/vault/creds {fd}>& {}/vault/x", p.root, p.root),
                &p.root,
            ),
            "deny",
            "{fd}>&",
        );
    }
}

#[skuld::test]
fn hook_close_form_operand_cannot_hide_a_denied_path(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `cp >&-vault/creds stolen.txt` copies the deny-listed file: bash reports
    // `argc=2 [vault/creds stolen.txt]`, so the operand is a real argument.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cp *)"],"deny":["Read(//{abs}/vault/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(
            &format!("cp >&-{}/vault/creds {}/stolen.txt", p.root, p.root),
            &p.root,
        ),
        "deny",
    );
}

#[skuld::test]
fn hook_command_less_redirect_denies(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `> file` truncates it with nothing to run. The verdict has to come from
    // the file rules alone: there is no command name to hang a Bash rule on.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cat *)"],"deny":["Write(//{abs}/vault/**)"]}}"#),
    );
    for cmd in ["> {root}/vault/creds", "FOO=x > {root}/vault/creds"] {
        assert_eq!(
            run_bash_hook(&cmd.replace("{root}", &p.root), &p.root),
            "deny",
            "{cmd}",
        );
    }
}

#[skuld::test]
fn hook_close_input_form_operand_cannot_hide_a_denied_path(
    #[fixture(temp_dir)] dir: &std::path::Path,
) {
    // The read-side mirror of `>&-word`: `cat <&-vault/creds` closes stdin and
    // passes the deny-listed path as an argument.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(cat *)"],"deny":["Read(//{abs}/vault/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(&format!("cat <&-{}/vault/creds", p.root), &p.root),
        "deny",
    );
}

#[skuld::test]
fn hook_dynamic_operand_holds_its_position(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `grep <pattern> <file>` reads its second positional and skips its first,
    // so dropping the unresolved operand slides the deny-listed path into the
    // slot nothing reads.
    let abs = vault_paths(dir).root;
    let p = write_vault_project(
        dir,
        &format!(r#"{{"allow":["Bash(grep *)"],"deny":["Read(//{abs}/vault/**)"]}}"#),
    );
    assert_eq!(
        run_bash_hook(&format!("grep >&-$P {}/vault/creds", p.root), &p.root),
        "deny",
    );
}
