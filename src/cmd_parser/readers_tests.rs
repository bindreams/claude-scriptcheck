use super::readers::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn reads(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn writes(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[test]
fn cat_basic() {
    let r = CatParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
    assert!(r.writes.is_empty());
}

#[test]
fn cat_with_flags() {
    let r = CatParser.parse(&["-n", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn cat_multiple_files() {
    let r = CatParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

// ── head ──

#[test]
fn head_n_value_not_treated_as_file() {
    let r = HeadParser.parse(&["-n", "5", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn head_bytes_value_not_treated_as_file() {
    let r = HeadParser.parse(&["-c", "100", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn head_no_args() {
    let r = HeadParser.parse(&[], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[test]
fn head_legacy_dash_number() {
    let r = HeadParser.parse(&["-30", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn head_legacy_dash_1() {
    let r = HeadParser.parse(&["-1", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn head_legacy_dash_number_no_file() {
    let r = HeadParser.parse(&["-30"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[test]
fn head_legacy_dash_number_multiple_files() {
    let r = HeadParser.parse(&["-5", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

#[test]
fn head_legacy_with_suffix() {
    let r = HeadParser.parse(&["-30b", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn head_legacy_with_k_suffix() {
    let r = HeadParser.parse(&["-30k", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── tail ──

#[test]
fn tail_n_value_not_treated_as_file() {
    let r = TailParser.parse(&["-n", "20", "log.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/log.txt"]));
}

#[test]
fn tail_legacy_dash_number() {
    let r = TailParser.parse(&["-30", "log.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/log.txt"]));
}

#[test]
fn tail_legacy_plus_number() {
    let r = TailParser.parse(&["+30", "log.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/log.txt"]));
}

#[test]
fn tail_legacy_dash_number_with_follow() {
    let r = TailParser.parse(&["-30f", "log.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/log.txt"]));
}

#[test]
fn tail_legacy_plus_number_with_suffix() {
    let r = TailParser.parse(&["+30lf", "log.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/log.txt"]));
}

#[test]
fn tail_legacy_bytes_suffix() {
    let r = TailParser.parse(&["-30c", "log.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/log.txt"]));
}

// ── strip_legacy_numeric ──

#[test]
fn wc_flags_are_boolean() {
    let r = WcParser.parse(&["-l", "-w", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── cut ──

#[test]
fn cut_field_value_not_treated_as_file() {
    let r = CutParser.parse(&["-f", "1,2", "-d", ",", "data.csv"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.csv"]));
}

// ── rm ──

#[test]
fn head_unknown_flag_fails() {
    let r = HeadParser.parse(&["--nonexistent-flag", "file.txt"], "/tmp");
    assert!(r.is_err());
}

// ── tac / nl / paste / rev / expand / unexpand / fold / column / od ──

#[test]
fn tac_reads_files() {
    let r = TacParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn nl_value_flags_not_files() {
    let r = NlParser.parse(&["-b", "a", "-w", "6", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn paste_delim_not_file() {
    let r = PasteParser.parse(&["-d", ",", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

#[test]
fn rev_reads_files() {
    let r = RevParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn expand_tabstop_not_file() {
    let r = ExpandParser.parse(&["-t", "4", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn unexpand_tabstop_not_file() {
    let r = UnexpandParser.parse(&["-t", "4", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn fold_width_not_file() {
    let r = FoldParser.parse(&["-w", "80", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn column_separator_not_file() {
    let r = ColumnParser.parse(&["-s", ",", "-t", "data.csv"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.csv"]));
}

#[test]
fn od_skip_not_file() {
    let r = OdParser.parse(&["-A", "x", "-t", "x1", "-j", "10", "file.bin"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.bin"]));
}

// ── zcat / bzcat / xzcat / readlink / du / lsof ──

#[test]
fn zcat_reads_files() {
    let r = ZcatParser.parse(&["file.gz"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.gz"]));
}

#[test]
fn bzcat_reads_files() {
    let r = BzcatParser.parse(&["file.bz2"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.bz2"]));
}

#[test]
fn xzcat_reads_files() {
    let r = XzcatParser.parse(&["file.xz"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.xz"]));
}

#[test]
fn readlink_reads_file() {
    let r = ReadlinkParser.parse(&["-f", "link"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/link"]));
}

#[test]
fn du_reads_dirs() {
    let r = DuParser.parse(&["-sh", "dir1", "dir2"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir1", "/tmp/dir2"]));
}

#[test]
fn du_max_depth_not_file() {
    let r = DuParser.parse(&["-d", "2", "dir/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
}

#[test]
fn lsof_reads_files() {
    let r = LsofParser.parse(&["/tmp/file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn lsof_value_flags_not_files() {
    let r = LsofParser.parse(&["-p", "1234", "-i", ":8080"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

// ── truncate ──

#[test]
fn cat_bsd_line_buffered() {
    // BSD cat -l (line buffering)
    let r = CatParser.parse(&["-ln", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn stat_bsd_verbose() {
    // macOS stat -x (verbose format)
    let r = StatParser.parse(&["-x", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn stat_bsd_raw() {
    // macOS stat -r (raw output)
    let r = StatParser.parse(&["-r", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn stat_bsd_ls_format() {
    // macOS stat -l (ls -lT format)
    let r = StatParser.parse(&["-l", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn du_bsd_exclude_pattern() {
    // BSD du -I PATTERN (exclude, equivalent to GNU --exclude)
    let r = DuParser.parse(&["-I", "*.o", "src/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
}

#[test]
fn du_gnu_exclude() {
    // GNU du --exclude=PATTERN
    let r = DuParser.parse(&["--exclude", "*.o", "src/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
}

// ── tar BSD vs GNU ──

#[test]
fn tar_bsd_extract_with_verbose() {
    // bsdtar style: tar -xvf archive.tar
    let r = super::tar::TarParser.parse(
        &["-xvf", "archive.tar"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.tar"]));
}

#[test]
fn tar_gnu_long_flags() {
    // GNU tar with long flags
    let r = super::tar::TarParser.parse(
        &["--extract", "--verbose", "--file", "archive.tar", "--directory", "/dest"],
        "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.tar"]));
    assert_eq!(r.writes, writes(&["/dest"]));
}

#[test]
fn tar_gnu_gzip_flag() {
    // GNU tar -z (gzip compression) — should not fail
    let r = super::tar::TarParser.parse(
        &["-czf", "archive.tar.gz", "dir/"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.tar.gz"]));
}

#[test]
fn tar_gnu_xz_flag() {
    // GNU tar -J (xz compression)
    let r = super::tar::TarParser.parse(
        &["-cJf", "archive.tar.xz", "dir/"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.tar.xz"]));
}

#[test]
fn tar_gnu_bzip2_flag() {
    // GNU tar -j (bzip2 compression)
    let r = super::tar::TarParser.parse(
        &["-cjf", "archive.tar.bz2", "src/"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.tar.bz2"]));
}

// ── sed BSD vs GNU ──

// ── base64 ──

#[test]
fn base64_stdin() {
    let r = Base64Parser.parse(&[], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert!(r.writes.is_empty());
}

#[test]
fn base64_positional_file() {
    let r = Base64Parser.parse(&["file.bin"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.bin"]));
    assert!(r.writes.is_empty());
}

#[test]
fn base64_decode_positional() {
    let r = Base64Parser.parse(&["-d", "encoded.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/encoded.txt"]));
    assert!(r.writes.is_empty());
}

#[test]
fn base64_input_flag() {
    let r = Base64Parser.parse(&["-i", "file.bin"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.bin"]));
    assert!(r.writes.is_empty());
}

#[test]
fn base64_output_flag() {
    let r = Base64Parser.parse(&["-o", "out.txt"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

#[test]
fn base64_both_flags() {
    let r = Base64Parser.parse(&["-i", "in.bin", "-o", "out.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/in.bin"]));
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

#[test]
fn base64_long_flags() {
    let r = Base64Parser.parse(&["--input", "in.bin", "--output", "out.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/in.bin"]));
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

// ── sha1sum ──

#[test]
fn sha1sum_basic() {
    let r = Sha1sumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
    assert!(r.writes.is_empty());
}

#[test]
fn sha1sum_check() {
    let r = Sha1sumParser.parse(&["-c", "sums.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/sums.txt"]));
}

#[test]
fn sha1sum_multiple() {
    let r = Sha1sumParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

// ── sha512sum ──

#[test]
fn sha512sum_basic() {
    let r = Sha512sumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── sha224sum ──

#[test]
fn sha224sum_basic() {
    let r = Sha224sumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── sha384sum ──

#[test]
fn sha384sum_basic() {
    let r = Sha384sumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── b2sum ──

#[test]
fn b2sum_basic() {
    let r = B2sumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn b2sum_with_length() {
    let r = B2sumParser.parse(&["--length", "256", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── cksum ──

#[test]
fn cksum_basic() {
    let r = CksumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn cksum_multiple() {
    let r = CksumParser.parse(&["a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
}

// ── sum ──

#[test]
fn sum_basic() {
    let r = SumParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn sum_with_flag() {
    let r = SumParser.parse(&["-r", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── md5 (macOS) ──

#[test]
fn md5_basic() {
    let r = Md5Parser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn md5_string_flag() {
    // md5 -s "hello" hashes the string, not a file
    let r = Md5Parser.parse(&["-s", "hello"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[test]
fn md5_quiet_with_file() {
    let r = Md5Parser.parse(&["-q", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── otool (macOS) ──

#[test]
fn otool_shared_libs() {
    let r = OtoolParser.parse(&["-L", "/usr/bin/true"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/usr/bin/true"]));
}

#[test]
fn otool_load_commands() {
    let r = OtoolParser.parse(&["-l", "binary"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/binary"]));
}

#[test]
fn otool_multiple_flags() {
    let r = OtoolParser.parse(&["-l", "-v", "binary"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/binary"]));
}
