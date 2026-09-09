use super::filesystem::*;
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

fn reads(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

fn writes(paths: &[&str]) -> Vec<AccessScope> {
    paths
        .iter()
        .map(|s| AccessScope::Exact(s.to_string()))
        .collect()
}

#[skuld::test]
fn cp_basic() {
    let r = CpParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[skuld::test]
fn cp_with_t_flag() {
    let r = CpParser
        .parse(&["-t", "/dest", "src1.txt", "src2.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src1.txt", "/tmp/src2.txt"]));
    // -t names a directory, so each source lands beneath it.
    assert_eq!(
        r.writes,
        writes(&["/dest", "/dest/src1.txt", "/dest/src2.txt"]),
    );
}

#[skuld::test]
fn cp_recursive() {
    let r = CpParser.parse(&["-r", "src/", "dst/"], "/tmp").unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src/"]));
    assert_eq!(r.writes, sub(&["/tmp/dst/"]));
}

// ── mv ──

#[skuld::test]
fn mv_basic(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("old.txt"), "x").unwrap();
    let r = MvParser.parse(&["old.txt", "new.txt"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/old.txt")]));
    assert_eq!(r.writes, writes(&[&format!("{cwd}/new.txt")]));
}

#[skuld::test]
fn mv_with_t_flag(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("file1"), "x").unwrap();
    std::fs::write(dir.join("file2"), "x").unwrap();
    let r = MvParser
        .parse(&["-t", "/dest", "file1", "file2"], &cwd)
        .unwrap();
    assert_eq!(
        r.reads,
        reads(&[&format!("{cwd}/file1"), &format!("{cwd}/file2")]),
    );
    // -t names a directory, so each source lands beneath it.
    assert_eq!(r.writes, writes(&["/dest", "/dest/file1", "/dest/file2"]),);
}

// ── ln ──

#[skuld::test]
fn ln_basic() {
    let r = LnParser.parse(&["-s", "target", "link"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/target"]));
    assert_eq!(r.writes, writes(&["/tmp/link"]));
}

// ── install ──

#[skuld::test]
fn install_basic() {
    let r = InstallParser.parse(&["src", "dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

#[skuld::test]
fn install_d_flag() {
    let r = InstallParser
        .parse(&["-d", "dir1", "dir2"], "/tmp")
        .unwrap();
    assert!(r.reads.is_empty());
    assert_eq!(r.writes, writes(&["/tmp/dir1", "/tmp/dir2"]));
}

#[skuld::test]
fn install_t_flag() {
    let r = InstallParser
        .parse(&["-t", "/dest", "src1", "src2"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src1", "/tmp/src2"]));
    // -t names a directory, so each source lands beneath it.
    assert_eq!(r.writes, writes(&["/dest", "/dest/src1", "/dest/src2"]));
}

#[skuld::test]
fn install_mode_value_not_file() {
    let r = InstallParser
        .parse(&["-m", "755", "src", "dest"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

// ── mkdir ──

#[skuld::test]
fn mkdir_basic() {
    let r = MkdirParser.parse(&["foo"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/foo"]));
}

#[skuld::test]
fn mkdir_p_flag() {
    let r = MkdirParser.parse(&["-p", "a/b/c"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/a/b/c"]));
}

#[skuld::test]
fn mkdir_mode_value_not_file() {
    let r = MkdirParser.parse(&["-m", "755", "foo"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/foo"]));
}

// ── touch ──

#[skuld::test]
fn touch_basic() {
    let r = TouchParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn touch_t_value_not_file() {
    let r = TouchParser
        .parse(&["-t", "202301010000", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// ── diff ──

#[skuld::test]
fn diff_two_files() {
    let r = DiffParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

#[skuld::test]
fn diff_u_value_not_file() {
    let r = DiffParser
        .parse(&["-U", "3", "a.txt", "b.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

// ── sort ──

#[skuld::test]
fn sort_basic() {
    let r = SortParser.parse(&["data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
    assert!(r.writes.is_empty());
}

#[skuld::test]
fn sort_o_is_write() {
    let r = SortParser
        .parse(&["-o", "out.txt", "in.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/in.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

#[skuld::test]
fn sort_k_value_not_file() {
    let r = SortParser
        .parse(&["-k", "2", "-t", ",", "data.csv"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.csv"]));
}

// ── uniq ──

#[skuld::test]
fn uniq_input_only() {
    let r = UniqParser.parse(&["input.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/input.txt"]));
    assert!(r.writes.is_empty());
}

#[skuld::test]
fn uniq_input_and_output() {
    let r = UniqParser
        .parse(&["input.txt", "output.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/input.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/output.txt"]));
}

#[skuld::test]
fn uniq_f_value_not_file() {
    let r = UniqParser.parse(&["-f", "2", "input.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/input.txt"]));
}

// ── chmod / chown / chgrp ──

#[skuld::test]
fn chmod_mode_then_files() {
    let r = ChmodParser.parse(&["755", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn chmod_recursive() {
    let r = ChmodParser.parse(&["-R", "755", "dir/"], "/tmp").unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir/"]));
}

#[skuld::test]
fn chown_owner_then_files() {
    let r = ChownParser
        .parse(&["root:root", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn chgrp_group_then_files() {
    let r = ChgrpParser.parse(&["wheel", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// ── source ──

#[skuld::test]
fn source_reads_file() {
    let r = SourceParser.parse(&["/tmp/script.sh"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.sh"]));
}

#[skuld::test]
fn source_ignores_script_args() {
    let r = SourceParser
        .parse(&["script.sh", "arg1", "arg2"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.sh"]));
}

#[skuld::test]
fn source_no_args() {
    let r = SourceParser.parse(&[], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

// ── parse failure ──

#[skuld::test]
fn cp_selinux_z_flag() {
    let r = CpParser.parse(&["-Z", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[skuld::test]
fn cp_selinux_context_flag() {
    let r = CpParser
        .parse(
            &["--context=system_u:object_r:tmp_t", "a.txt", "b.txt"],
            "/tmp",
        )
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[skuld::test]
fn mv_selinux_z_flag(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("old.txt"), "x").unwrap();
    let r = MvParser.parse(&["-Z", "old.txt", "new.txt"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/old.txt")]));
    assert_eq!(r.writes, writes(&[&format!("{cwd}/new.txt")]));
}

#[skuld::test]
fn mv_selinux_context_flag(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = MvParser
        .parse(
            &[
                "--context=unconfined_u:object_r:user_home_t",
                "a.txt",
                "b.txt",
            ],
            &cwd,
        )
        .unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/a.txt")]));
    assert_eq!(r.writes, writes(&[&format!("{cwd}/b.txt")]));
}

#[skuld::test]
fn mkdir_selinux_z_flag() {
    let r = MkdirParser.parse(&["-Z", "newdir"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/newdir"]));
}

#[skuld::test]
fn mkdir_selinux_context_flag() {
    let r = MkdirParser
        .parse(&["--context=system_u:object_r:tmp_t", "newdir"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/newdir"]));
}

#[skuld::test]
fn install_selinux_z_flag() {
    let r = InstallParser.parse(&["-Z", "src", "dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

#[skuld::test]
fn install_selinux_context_flag() {
    let r = InstallParser
        .parse(
            &[
                "--context=system_u:object_r:bin_t",
                "-m",
                "755",
                "src",
                "dest",
            ],
            "/tmp",
        )
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

// ══════════════════════════════════════════════════════════════════════
// BSD/macOS variant tests
// ══════════════════════════════════════════════════════════════════════

#[skuld::test]
fn cp_bsd_clone_flag() {
    // macOS cp -c (clonefile)
    let r = CpParser.parse(&["-c", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[skuld::test]
fn sed_bsd_inplace_empty_suffix() {
    // macOS sed requires: sed -i '' 's/foo/bar/' file
    // The '' is the explicit empty suffix, followed by the script
    let r = super::sed::SedParser
        .parse(&["-i", "s/foo/bar/", "file.txt"], "/tmp")
        .unwrap();
    // -i is detected, s/foo/bar/ is the script (first non-flag positional), file.txt is the target
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[skuld::test]
fn sed_gnu_extended_regexp() {
    // GNU sed -E (extended regex)
    let r = super::sed::SedParser
        .parse(&["-E", "s/foo+/bar/", "file.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── grep GNU vs BSD ──

#[skuld::test]
fn sort_gnu_parallel() {
    // GNU sort --parallel (not on BSD)
    let r = SortParser
        .parse(&["--parallel", "4", "data.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

#[skuld::test]
fn sort_gnu_compress_program() {
    // GNU sort --compress-program (not on BSD)
    let r = SortParser
        .parse(&["--compress-program", "gzip", "data.txt"], "/tmp")
        .unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

// ── gzip/bzip2/xz with BSD-style level flags ──

#[skuld::test]
fn chmod_bsd_silent() {
    // BSD chmod -f (silent) — already defined as short+long
    let r = ChmodParser.parse(&["-fR", "755", "dir/"], "/tmp").unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir/"]));
}

#[skuld::test]
fn chown_bsd_no_dereference() {
    // BSD chown -h (don't follow symlinks)
    let r = ChownParser
        .parse(&["-h", "root:wheel", "link"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/link"]));
}

// ── touch macOS flags ──

#[skuld::test]
fn touch_bsd_access_time_flag() {
    // macOS touch -A (adjust access time) — recognized as bool
    let r = TouchParser.parse(&["-A", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// Recursion scopes ====================================================================================================

#[skuld::test]
fn diff_recursive_operands_are_subtree() {
    let r = DiffParser.parse(&["-r", "a", "b"], "/tmp").unwrap();
    assert_eq!(r.reads, sub(&["/tmp/a", "/tmp/b"]));
}

#[skuld::test]
fn diff_without_r_operands_are_exact() {
    let r = DiffParser.parse(&["a", "b"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a", "/tmp/b"]));
}

#[skuld::test]
fn cp_recursive_sources_are_subtree() {
    let r = CpParser.parse(&["-r", "src", "dst"], "/tmp").unwrap();
    assert_eq!(r.reads, sub(&["/tmp/src"]));
    assert_eq!(r.writes, sub(&["/tmp/dst"]));
}

#[skuld::test]
fn cp_without_r_sources_are_exact() {
    let r = CpParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

// Recursive writes and directory destinations =========================================================================

#[skuld::test]
fn chmod_recursive_targets_are_subtree() {
    let r = ChmodParser
        .parse(&["-R", "755", "/tmp/dir"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir"]));
}

#[skuld::test]
fn chown_recursive_targets_are_subtree() {
    let r = ChownParser
        .parse(&["-R", "me:me", "/tmp/dir"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir"]));
}

#[skuld::test]
fn chgrp_recursive_targets_are_subtree() {
    let r = ChgrpParser
        .parse(&["-R", "staff", "/tmp/dir"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir"]));
}

#[skuld::test]
fn chmod_without_r_targets_are_exact() {
    let r = ChmodParser.parse(&["755", "/tmp/f"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/f"]));
}

#[skuld::test]
fn cp_file_into_existing_directory_writes_nested_path(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `cp a.txt vault` writes `vault/a.txt`; recording only `vault` lets the
    // write slip past a rule scoped to the directory's contents.
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("vault")).unwrap();
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = CpParser.parse(&["a.txt", "vault"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/a.txt")]));
    assert_eq!(
        r.writes,
        writes(&[&format!("{cwd}/vault"), &format!("{cwd}/vault/a.txt")]),
    );
}

#[skuld::test]
fn cp_to_nonexistent_destination_is_exact(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = CpParser.parse(&["a.txt", "b.txt"], &cwd).unwrap();
    assert_eq!(r.writes, writes(&[&format!("{cwd}/b.txt")]));
}

#[skuld::test]
fn cp_target_directory_flag_writes_nested_path(#[fixture(temp_dir)] dir: &std::path::Path) {
    // -t always names a directory, so no stat is needed.
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = CpParser.parse(&["-t", "vault", "a.txt"], &cwd).unwrap();
    assert_eq!(
        r.writes,
        writes(&[&format!("{cwd}/vault"), &format!("{cwd}/vault/a.txt")]),
    );
}

#[skuld::test]
fn cp_no_target_directory_flag_is_exact(#[fixture(temp_dir)] dir: &std::path::Path) {
    // -T means the destination is the path itself, even if it is a directory.
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("vault")).unwrap();
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = CpParser.parse(&["-T", "a.txt", "vault"], &cwd).unwrap();
    assert_eq!(r.writes, writes(&[&format!("{cwd}/vault")]));
}

#[skuld::test]
fn mv_directory_source_is_subtree(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    let r = MvParser.parse(&["src", "dst"], &cwd).unwrap();
    assert_eq!(r.reads, sub(&[&format!("{cwd}/src")]));
}

#[skuld::test]
fn mv_file_source_is_exact(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = MvParser.parse(&["a.txt", "b.txt"], &cwd).unwrap();
    assert_eq!(r.reads, reads(&[&format!("{cwd}/a.txt")]));
}

#[skuld::test]
fn mv_multiple_sources_are_each_classified(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("srcdir")).unwrap();
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    std::fs::create_dir(dir.join("vault")).unwrap();
    let r = MvParser.parse(&["srcdir", "a.txt", "vault"], &cwd).unwrap();
    assert_eq!(
        r.reads,
        vec![
            AccessScope::Subtree(format!("{cwd}/srcdir")),
            AccessScope::Exact(format!("{cwd}/a.txt")),
        ],
    );
}

#[skuld::test]
fn mv_into_existing_directory_writes_nested_path(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("vault")).unwrap();
    std::fs::write(dir.join("secret.txt"), "x").unwrap();
    let r = MvParser.parse(&["secret.txt", "vault"], &cwd).unwrap();
    assert_eq!(
        r.writes,
        writes(&[&format!("{cwd}/vault"), &format!("{cwd}/vault/secret.txt")]),
    );
}

#[skuld::test]
fn ln_into_existing_directory_writes_nested_path(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("vault")).unwrap();
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = LnParser.parse(&["-s", "a.txt", "vault"], &cwd).unwrap();
    assert_eq!(
        r.writes,
        writes(&[&format!("{cwd}/vault"), &format!("{cwd}/vault/a.txt")]),
    );
}

#[skuld::test]
fn install_into_existing_directory_writes_nested_path(#[fixture(temp_dir)] dir: &std::path::Path) {
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("vault")).unwrap();
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = InstallParser.parse(&["a.txt", "vault"], &cwd).unwrap();
    assert_eq!(
        r.writes,
        writes(&[&format!("{cwd}/vault"), &format!("{cwd}/vault/a.txt")]),
    );
}

#[skuld::test]
fn cp_recursive_dereference_is_following() {
    let r = CpParser.parse(&["-rL", "src", "dst"], "/tmp").unwrap();
    assert_eq!(
        r.reads,
        vec![AccessScope::UnboundedSubtree("/tmp/src".into())],
    );
}

#[skuld::test]
fn cp_dereference_without_recursion_stays_exact() {
    let r = CpParser.parse(&["-L", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
}

#[skuld::test]
fn chown_recursive_dereference_is_following() {
    let r = ChownParser
        .parse(&["-R", "-L", "me", "/tmp/dir"], "/tmp")
        .unwrap();
    assert_eq!(
        r.writes,
        vec![AccessScope::UnboundedSubtree("/tmp/dir".into())],
    );
}

#[skuld::test]
fn chgrp_recursive_dereference_is_following() {
    let r = ChgrpParser
        .parse(&["-R", "-H", "staff", "/tmp/dir"], "/tmp")
        .unwrap();
    assert_eq!(
        r.writes,
        vec![AccessScope::UnboundedSubtree("/tmp/dir".into())],
    );
}

#[skuld::test]
fn chmod_recursive_has_no_dereference_flag() {
    // chmod declares neither -L nor -H; the shared helper must not trip on that.
    let r = ChmodParser
        .parse(&["-R", "755", "/tmp/dir"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, sub(&["/tmp/dir"]));
}

#[skuld::test]
fn cp_dot_source_lands_contents_under_destination(#[fixture(temp_dir)] dir: &std::path::Path) {
    // `cp -r src/. vault` writes vault/<entry> for every entry, with no single
    // landing path to name.
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::create_dir(dir.join("src")).unwrap();
    std::fs::create_dir(dir.join("vault")).unwrap();
    let r = CpParser.parse(&["-r", "src/.", "vault"], &cwd).unwrap();
    assert_eq!(
        r.writes,
        vec![
            AccessScope::Exact(format!("{cwd}/vault")),
            AccessScope::Subtree(format!("{cwd}/vault")),
        ],
    );
}

#[skuld::test]
fn cp_destination_stat_error_other_than_missing_takes_directory_branch(
    #[fixture(temp_dir)] dir: &std::path::Path,
) {
    // A destination reported missing provably is not a directory, so the write
    // is the destination itself. Anything else leaves the question open.
    let cwd = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let r = CpParser.parse(&["a.txt", "gone/b.txt"], &cwd).unwrap();
    assert_eq!(r.writes, writes(&[&format!("{cwd}/gone/b.txt")]));
}

// Program execution ===================================================================================================

#[skuld::test]
fn sort_compress_program_requires_bash_rule() {
    let result = SortParser
        .parse(&["--compress-program", "/tmp/evil.sh", "big.txt"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
}

#[skuld::test]
fn sort_empty_compress_program_stays_file_only() {
    let result = SortParser
        .parse(&["--compress-program", "", "big.txt"], "/cwd")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn sort_plain_stays_file_only() {
    let result = SortParser.parse(&["big.txt"], "/cwd").unwrap();
    assert_eq!(result.file_only, None);
    assert_eq!(result.reads, reads(&["/cwd/big.txt"]));
}
