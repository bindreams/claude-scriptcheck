use super::tar::*;
use super::CommandParser;
use crate::file_access::AccessScope;
use pretty_assertions::assert_eq;

fn sub(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Subtree(s.to_string()))
        .collect()
}

#[allow(dead_code)]
fn unbounded(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::UnboundedSubtree(s.to_string()))
        .collect()
}

fn r(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

fn w(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn tar_create_mode(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("dir")).unwrap();
    let result = TarParser
        .parse(&["-cf", "archive.tar", "dir/"], &cwd)
        .unwrap();
    assert_eq!(result.reads, sub(&[&format!("{cwd}/dir/")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/archive.tar")]));
}

#[skuld::test]
fn tar_extract_mode() {
    // Extraction without -C unpacks into the working directory.
    let result = TarParser.parse(&["-xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    assert_eq!(result.writes, sub(&["/tmp"]));
}

#[skuld::test]
fn tar_extract_to_dir() {
    let result = TarParser
        .parse(&["-xf", "a.tar", "-C", "/dest"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/a.tar"]));
    assert_eq!(result.writes, sub(&["/dest"]));
}

#[skuld::test]
fn tar_legacy_syntax() {
    let result = TarParser.parse(&["xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_legacy_create(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let result = TarParser
        .parse(&["czf", "archive.tar.gz", "src/"], &cwd)
        .unwrap();
    assert_eq!(result.reads, sub(&[&format!("{cwd}/src/")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/archive.tar.gz")]));
}

#[skuld::test]
fn tar_list_mode() {
    let result = TarParser.parse(&["-tf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[skuld::test]
fn tar_long_flags(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    let result = TarParser
        .parse(
            &[
                "--create",
                "--file",
                "archive.tar",
                "--directory",
                "/src",
                ".",
            ],
            &cwd,
        )
        .unwrap();
    // `--directory /src` puts `.` at /src, so that is what gets archived —
    // verified against GNU tar 1.35. The archive itself stays relative to the
    // working directory: tar opens it before changing directory.
    assert_eq!(result.reads, sub(&["/src/."]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/archive.tar")]));
}

#[skuld::test]
fn tar_long_flag_equals() {
    let result = TarParser
        .parse(&["--extract", "--file=archive.tar"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

// Recursion scopes ====================================================================================================

#[skuld::test]
fn tar_create_directory_source_is_subtree(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let result = TarParser.parse(&["cf", "a.tar", "src"], &cwd).unwrap();
    assert_eq!(result.reads, sub(&[&format!("{cwd}/src")]));
    assert_eq!(result.writes, w(&[&format!("{cwd}/a.tar")]));
}

#[skuld::test]
fn tar_create_file_source_is_exact(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    let result = TarParser.parse(&["cf", "a.tar", "f.txt"], &cwd).unwrap();
    assert_eq!(result.reads, r(&[&format!("{cwd}/f.txt")]));
}

#[skuld::test]
fn tar_dereference_is_following(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let result = TarParser
        .parse(&["-c", "-h", "-f", "a.tar", "src"], &cwd)
        .unwrap();
    assert_eq!(result.reads, unbounded(&[&format!("{cwd}/src")]));
}

#[skuld::test]
fn tar_extract_change_dir_is_subtree() {
    let result = TarParser
        .parse(&["xf", "/tmp/a.tar", "-C", "/dest"], "/tmp")
        .unwrap();
    assert_eq!(result.reads, r(&["/tmp/a.tar"]));
    assert_eq!(result.writes, sub(&["/dest"]));
}

#[skuld::test]
fn tar_extract_without_c_writes_cwd() {
    let result = TarParser.parse(&["xf", "/tmp/a.tar"], "/tmp/proj").unwrap();
    assert_eq!(result.writes, sub(&["/tmp/proj"]));
}

// Program execution ===================================================================================================

#[skuld::test]
fn tar_use_compress_program_requires_bash_rule() {
    for args in [
        vec![
            "--use-compress-program",
            "/tmp/evil.sh",
            "-cf",
            "a.tar",
            "sub",
        ],
        vec!["--use-compress-program=/tmp/evil.sh", "-cf", "a.tar", "sub"],
    ] {
        let result = TarParser.parse(&args, "/cwd").unwrap();
        assert_eq!(result.file_only, Some(false), "{args:?}");
    }
}

#[skuld::test]
fn tar_program_long_flags_require_bash_rule() {
    for flag in [
        "--to-command",
        "--rmt-command",
        "--rsh-command",
        "--info-script",
        "--new-volume-script",
        "--checkpoint-action",
    ] {
        let result = TarParser
            .parse(&[flag, "/tmp/evil.sh", "-cf", "a.tar", "sub"], "/cwd")
            .unwrap();
        assert_eq!(result.file_only, Some(false), "{flag}");
    }
}

#[skuld::test]
fn tar_short_i_requires_bash_rule() {
    // GNU's `-I` is `--use-compress-program`; bsdtar reads it as a name list.
    // Treated as exec-capable on every platform — a prompt, never a hole.
    let result = TarParser
        .parse(&["-I", "zstd", "-cf", "a.tar.zst", "sub"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn tar_short_f_info_script_requires_bash_rule() {
    let result = TarParser
        .parse(&["-F", "/tmp/evil.sh", "-cf", "a.tar", "sub"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn tar_legacy_bundle_i_requires_bash_rule() {
    // The no-dash bundled form. Only `file_only` is asserted: the legacy bundle
    // consumes its values in a fixed order rather than the order the letters
    // appear, a pre-existing approximation this does not change.
    let result = TarParser
        .parse(&["cIf", "/tmp/evil.sh", "a.tar", "sub"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn tar_exec_flag_value_is_not_a_positional_read() {
    let result = TarParser
        .parse(
            &[
                "--use-compress-program",
                "/tmp/comp.sh",
                "-cf",
                "a.tar",
                "sub",
            ],
            "/cwd",
        )
        .unwrap();
    assert_eq!(result.reads, sub(&["/cwd/sub"]));
}

#[skuld::test]
fn tar_plain_create_stays_file_only() {
    let result = TarParser.parse(&["cf", "out.tar", "sub"], "/cwd").unwrap();
    assert_eq!(result.file_only, None);
    assert_eq!(result.writes, w(&["/cwd/out.tar"]));
    assert_eq!(result.reads, sub(&["/cwd/sub"]));
}

// Long-option abbreviations ===========================================================================================

#[skuld::test]
fn tar_abbreviated_exec_options_require_bash_rule() {
    // GNU tar 1.35 executes the program for every one of these spellings.
    for arg in [
        "--use-compress-program=/tmp/evil.sh",
        "--use-compress-prog=/tmp/evil.sh",
        "--use-compress=/tmp/evil.sh",
        "--use-comp=/tmp/evil.sh",
        "--use=/tmp/evil.sh",
        "--to-comm=/tmp/evil.sh",
        "--rmt-comm=/tmp/evil.sh",
        "--info-scr=/tmp/evil.sh",
        "--new-vol=/tmp/evil.sh",
        "--checkpoint-a=exec=/tmp/evil.sh",
    ] {
        let result = TarParser
            .parse(&[arg, "-cf", "a.tar", "sub"], "/cwd")
            .unwrap();
        assert_eq!(result.file_only, Some(false), "{arg}");
    }
}

#[skuld::test]
fn tar_abbreviated_exec_option_with_separate_value_requires_bash_rule() {
    let result = TarParser
        .parse(
            &["--use-comp", "/tmp/evil.sh", "-cf", "a.tar", "sub"],
            "/cwd",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(false));
    // The program name is consumed, not read as a member to archive.
    assert_eq!(result.reads, sub(&["/cwd/sub"]));
}

#[skuld::test]
fn tar_checkpoint_alone_stays_file_only() {
    // `--checkpoint` is a complete option and a strict prefix of
    // `--checkpoint-action`; the exact match wins, as in getopt_long.
    let result = TarParser
        .parse(&["--checkpoint=100", "-cf", "a.tar", "sub"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn tar_abbreviated_directory_resolves() {
    // `--dir` abbreviates `--directory`, so the extraction destination must be
    // recorded — otherwise the write lands somewhere unchecked.
    let result = TarParser
        .parse(&["--dir=/etc", "-xf", "a.tar"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, sub(&["/etc"]));
}

#[skuld::test]
fn tar_abbreviated_file_resolves() {
    let result = TarParser.parse(&["--fi=a.tar", "-x"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/cwd/a.tar"]));
}

#[skuld::test]
fn tar_ambiguous_long_abbreviation_is_skipped() {
    // `--d` could be --directory, --diff or --dereference. The real tar calls it
    // ambiguous and exits, so resolving it to nothing is right.
    let result = TarParser
        .parse(&["--d", "/etc", "-xf", "a.tar"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, None);
    assert!(!result
        .writes
        .contains(&AccessScope::Subtree("/etc".to_string())));
}

// -C / --directory in create mode =====================================================================================

#[skuld::test]
fn tar_create_positional_resolves_against_change_dir() {
    // `tar -cf out.tar -C /etc .` archives /etc, not the working directory
    // (verified against GNU tar 1.35).
    let result = TarParser
        .parse(&["-cf", "out.tar", "-C", "/nowhere", "."], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/nowhere/."]));
    assert_eq!(result.writes, w(&["/cwd/out.tar"]));
}

#[skuld::test]
fn tar_create_named_positional_resolves_against_change_dir() {
    let result = TarParser
        .parse(&["-cf", "out.tar", "-C", "/nowhere", "passwd"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/nowhere/passwd"]));
}

#[skuld::test]
fn tar_change_dir_applies_only_to_following_positionals() {
    // Verified: `tar -cf a.tar p.txt -C /tmp/one o.txt` takes p.txt from the
    // working directory and o.txt from /tmp/one.
    let result = TarParser
        .parse(
            &["-cf", "out.tar", "p.txt", "-C", "/nowhere", "o.txt"],
            "/cwd",
        )
        .unwrap();
    assert_eq!(result.reads, sub(&["/cwd/p.txt", "/nowhere/o.txt"]));
}

#[skuld::test]
fn tar_nested_change_dirs_compose() {
    // Verified: a relative second `-C` resolves against the first.
    let result = TarParser
        .parse(&["-cf", "out.tar", "-C", "/base", "-C", "sub", "f"], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/base/sub/f"]));
}

#[skuld::test]
fn tar_change_dir_long_form_applies_to_create() {
    let result = TarParser
        .parse(&["-cf", "out.tar", "--directory=/nowhere", "."], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/nowhere/."]));
}

#[skuld::test]
fn tar_legacy_bundle_change_dir_applies_to_create() {
    let result = TarParser
        .parse(&["cfC", "out.tar", "/nowhere", "."], "/cwd")
        .unwrap();
    assert_eq!(result.reads, sub(&["/nowhere/."]));
}

#[skuld::test]
fn tar_create_without_change_dir_still_uses_cwd() {
    let result = TarParser.parse(&["-cf", "out.tar", "src"], "/cwd").unwrap();
    assert_eq!(result.reads, sub(&["/cwd/src"]));
}

#[skuld::test]
fn tar_extract_records_every_change_dir_as_a_write() {
    // Members following each `-C` extract into that directory, so all of them
    // are write destinations. An absolute `-C` replaces the previous one.
    let result = TarParser
        .parse(&["-xf", "a.tar", "-C", "/d1", "-C", "/d2"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, sub(&["/d1", "/d2"]));
}

#[skuld::test]
fn tar_extract_relative_change_dir_composes() {
    let result = TarParser
        .parse(&["-xf", "a.tar", "-C", "/d1", "-C", "sub"], "/cwd")
        .unwrap();
    assert_eq!(result.writes, sub(&["/d1", "/d1/sub"]));
}
