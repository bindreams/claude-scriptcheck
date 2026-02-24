use super::filesystem::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn reads(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn writes(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[test]
fn cp_basic() {
    let r = CpParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[test]
fn cp_with_t_flag() {
    let r = CpParser.parse(&["-t", "/dest", "src1.txt", "src2.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src1.txt", "/tmp/src2.txt"]));
    assert_eq!(r.writes, writes(&["/dest"]));
}

#[test]
fn cp_recursive() {
    let r = CpParser.parse(&["-r", "src/", "dst/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
    assert_eq!(r.writes, writes(&["/tmp/dst/"]));
}

// ── mv ──

#[test]
fn mv_basic() {
    let r = MvParser.parse(&["old.txt", "new.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/old.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/new.txt"]));
}

#[test]
fn mv_with_t_flag() {
    let r = MvParser.parse(&["-t", "/dest", "file1", "file2"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file1", "/tmp/file2"]));
    assert_eq!(r.writes, writes(&["/dest"]));
}

// ── ln ──

#[test]
fn ln_basic() {
    let r = LnParser.parse(&["-s", "target", "link"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/target"]));
    assert_eq!(r.writes, writes(&["/tmp/link"]));
}

// ── install ──

#[test]
fn install_basic() {
    let r = InstallParser.parse(&["src", "dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

#[test]
fn install_d_flag() {
    let r = InstallParser.parse(&["-d", "dir1", "dir2"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert_eq!(r.writes, writes(&["/tmp/dir1", "/tmp/dir2"]));
}

#[test]
fn install_t_flag() {
    let r = InstallParser.parse(&["-t", "/dest", "src1", "src2"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src1", "/tmp/src2"]));
    assert_eq!(r.writes, writes(&["/dest"]));
}

#[test]
fn install_mode_value_not_file() {
    let r = InstallParser.parse(&["-m", "755", "src", "dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

// ── mkdir ──

#[test]
fn mkdir_basic() {
    let r = MkdirParser.parse(&["foo"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/foo"]));
}

#[test]
fn mkdir_p_flag() {
    let r = MkdirParser.parse(&["-p", "a/b/c"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/a/b/c"]));
}

#[test]
fn mkdir_mode_value_not_file() {
    let r = MkdirParser.parse(&["-m", "755", "foo"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/foo"]));
}

// ── touch ──

#[test]
fn touch_basic() {
    let r = TouchParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn touch_t_value_not_file() {
    let r = TouchParser.parse(&["-t", "202301010000", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// ── diff ──

#[test]
fn diff_two_files() {
    let r = DiffParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

#[test]
fn diff_u_value_not_file() {
    let r = DiffParser.parse(&["-U", "3", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

// ── sort ──

#[test]
fn sort_basic() {
    let r = SortParser.parse(&["data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
    assert!(r.writes.is_empty());
}

#[test]
fn sort_o_is_write() {
    let r = SortParser.parse(&["-o", "out.txt", "in.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/in.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

#[test]
fn sort_k_value_not_file() {
    let r = SortParser.parse(&["-k", "2", "-t", ",", "data.csv"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.csv"]));
}

// ── uniq ──

#[test]
fn uniq_input_only() {
    let r = UniqParser.parse(&["input.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/input.txt"]));
    assert!(r.writes.is_empty());
}

#[test]
fn uniq_input_and_output() {
    let r = UniqParser.parse(&["input.txt", "output.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/input.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/output.txt"]));
}

#[test]
fn uniq_f_value_not_file() {
    let r = UniqParser.parse(&["-f", "2", "input.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/input.txt"]));
}

// ── chmod / chown / chgrp ──

#[test]
fn chmod_mode_then_files() {
    let r = ChmodParser.parse(&["755", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn chmod_recursive() {
    let r = ChmodParser.parse(&["-R", "755", "dir/"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/dir/"]));
}

#[test]
fn chown_owner_then_files() {
    let r = ChownParser.parse(&["root:root", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn chgrp_group_then_files() {
    let r = ChgrpParser.parse(&["wheel", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// ── source ──

#[test]
fn source_reads_file() {
    let r = SourceParser.parse(&["/tmp/script.sh"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.sh"]));
}

#[test]
fn source_ignores_script_args() {
    let r = SourceParser.parse(&["script.sh", "arg1", "arg2"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.sh"]));
}

#[test]
fn source_no_args() {
    let r = SourceParser.parse(&[], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

// ── parse failure ──

#[test]
fn cp_selinux_z_flag() {
    let r = CpParser.parse(&["-Z", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[test]
fn cp_selinux_context_flag() {
    let r = CpParser.parse(&["--context=system_u:object_r:tmp_t", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[test]
fn mv_selinux_z_flag() {
    let r = MvParser.parse(&["-Z", "old.txt", "new.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/old.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/new.txt"]));
}

#[test]
fn mv_selinux_context_flag() {
    let r = MvParser.parse(&["--context=unconfined_u:object_r:user_home_t", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[test]
fn mkdir_selinux_z_flag() {
    let r = MkdirParser.parse(&["-Z", "newdir"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/newdir"]));
}

#[test]
fn mkdir_selinux_context_flag() {
    let r = MkdirParser.parse(&["--context=system_u:object_r:tmp_t", "newdir"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/newdir"]));
}

#[test]
fn install_selinux_z_flag() {
    let r = InstallParser.parse(&["-Z", "src", "dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

#[test]
fn install_selinux_context_flag() {
    let r = InstallParser.parse(&["--context=system_u:object_r:bin_t", "-m", "755", "src", "dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
    assert_eq!(r.writes, writes(&["/tmp/dest"]));
}

// ══════════════════════════════════════════════════════════════════════
// BSD/macOS variant tests
// ══════════════════════════════════════════════════════════════════════

#[test]
fn cp_bsd_clone_flag() {
    // macOS cp -c (clonefile)
    let r = CpParser.parse(&["-c", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/b.txt"]));
}

#[test]
fn sed_bsd_inplace_empty_suffix() {
    // macOS sed requires: sed -i '' 's/foo/bar/' file
    // The '' is the explicit empty suffix, followed by the script
    let r = super::sed::SedParser.parse(
        &["-i", "s/foo/bar/", "file.txt"], "/tmp",
    ).unwrap();
    // -i is detected, s/foo/bar/ is the script (first non-flag positional), file.txt is the target
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn sed_gnu_extended_regexp() {
    // GNU sed -E (extended regex)
    let r = super::sed::SedParser.parse(
        &["-E", "s/foo+/bar/", "file.txt"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── grep GNU vs BSD ──

#[test]
fn sort_gnu_parallel() {
    // GNU sort --parallel (not on BSD)
    let r = SortParser.parse(&["--parallel", "4", "data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

#[test]
fn sort_gnu_compress_program() {
    // GNU sort --compress-program (not on BSD)
    let r = SortParser.parse(&["--compress-program", "gzip", "data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

// ── gzip/bzip2/xz with BSD-style level flags ──

#[test]
fn chmod_bsd_silent() {
    // BSD chmod -f (silent) — already defined as short+long
    let r = ChmodParser.parse(&["-fR", "755", "dir/"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/dir/"]));
}

#[test]
fn chown_bsd_no_dereference() {
    // BSD chown -h (don't follow symlinks)
    let r = ChownParser.parse(&["-h", "root:wheel", "link"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/link"]));
}

// ── touch macOS flags ──

#[test]
fn touch_bsd_access_time_flag() {
    // macOS touch -A (adjust access time) — recognized as bool
    let r = TouchParser.parse(&["-A", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}
