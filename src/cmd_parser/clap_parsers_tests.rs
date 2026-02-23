use super::clap_parsers::*;
use super::CommandParser;
use pretty_assertions::assert_eq;


fn reads(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn writes(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

// ── cat ──

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
fn strip_legacy_dash_number() {
    assert_eq!(
        strip_legacy_numeric(&["-30", "file.txt"], false),
        vec!["file.txt"],
    );
}

#[test]
fn strip_legacy_dash_number_with_suffix() {
    assert_eq!(
        strip_legacy_numeric(&["-30b", "file.txt"], false),
        vec!["file.txt"],
    );
}

#[test]
fn strip_legacy_plus_number_allowed() {
    assert_eq!(
        strip_legacy_numeric(&["+30", "file.txt"], true),
        vec!["file.txt"],
    );
}

#[test]
fn strip_legacy_plus_number_disallowed() {
    assert_eq!(
        strip_legacy_numeric(&["+30", "file.txt"], false),
        vec!["+30", "file.txt"],
    );
}

#[test]
fn strip_legacy_normal_flags_unchanged() {
    assert_eq!(
        strip_legacy_numeric(&["-n", "5", "-v", "file.txt"], false),
        vec!["-n", "5", "-v", "file.txt"],
    );
}

#[test]
fn strip_legacy_bare_dash_unchanged() {
    assert_eq!(
        strip_legacy_numeric(&["-"], false),
        vec!["-"],
    );
}

#[test]
fn strip_legacy_after_separator_unchanged() {
    assert_eq!(
        strip_legacy_numeric(&["--", "-30"], false),
        vec!["--", "-30"],
    );
}

// ── wc ──

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
fn rm_basic() {
    let r = RmParser.parse(&["-rf", "/tmp/foo"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert_eq!(r.writes, writes(&["/tmp/foo"]));
}

#[test]
fn rm_double_dash() {
    let r = RmParser.parse(&["--", "-weird-file"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/-weird-file"]));
}

// ── tee ──

#[test]
fn tee_writes_files() {
    let r = TeeParser.parse(&["-a", "out.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/out.txt"]));
}

// ── grep ──

#[test]
fn grep_pattern_then_file() {
    let r = GrepParser.parse(&["TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn grep_e_flag_consumes_pattern() {
    let r = GrepParser.parse(&["-e", "TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn grep_multiple_e_flags() {
    let r = GrepParser.parse(&["-e", "TODO", "-e", "FIXME", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn grep_f_flag_is_read() {
    let r = GrepParser.parse(&["-f", "patterns.txt", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/patterns.txt", "/tmp/file.txt"]));
}

#[test]
fn grep_pattern_only_no_files() {
    let r = GrepParser.parse(&["pattern"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[test]
fn grep_with_value_flags() {
    let r = GrepParser.parse(&["-m", "10", "-A", "3", "pattern", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn grep_recursive_with_dir() {
    let r = GrepParser.parse(&["-r", "TODO", "/tmp/src"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src"]));
}

// ── rg ──

#[test]
fn rg_pattern_then_file() {
    let r = RgParser.parse(&["TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn rg_e_flag_consumes_pattern() {
    let r = RgParser.parse(&["-e", "TODO", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── awk ──

#[test]
fn awk_program_then_file() {
    let r = AwkParser.parse(&["/pattern/{ print }", "data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.txt"]));
}

#[test]
fn awk_program_only() {
    let r = AwkParser.parse(&["/pattern/{ print }"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[test]
fn awk_f_flag_is_read() {
    let r = AwkParser.parse(&["-f", "script.awk", "data.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/script.awk", "/tmp/data.txt"]));
}

#[test]
#[allow(non_snake_case)]
fn awk_F_value_not_treated_as_file() {
    let r = AwkParser.parse(&["-F", ",", "{ print $1 }", "data.csv"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.csv"]));
}

// ── cp ──

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
fn truncate_writes_files() {
    let r = TruncateParser.parse(&["-s", "0", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn truncate_size_not_file() {
    let r = TruncateParser.parse(&["--size", "1M", "a.bin", "b.bin"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/a.bin", "/tmp/b.bin"]));
}

// ── jq ──

#[test]
fn jq_filter_then_files() {
    let r = JqParser.parse(&[".name", "data.json"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.json"]));
}

#[test]
fn jq_filter_only() {
    let r = JqParser.parse(&["."], "/tmp").unwrap();
    assert!(r.reads.is_empty());
}

#[test]
fn jq_slurpfile_is_read() {
    let r = JqParser.parse(&["--slurpfile", "x", "data.json", "."], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/data.json"]));
}

#[test]
fn jq_from_file_makes_all_positionals_data() {
    let r = JqParser.parse(&["--from-file", "prog.jq", "a.json", "b.json"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/prog.jq", "/tmp/a.json", "/tmp/b.json"]));
}

// ── compression ──

#[test]
fn gzip_default_writes() {
    let r = GzipParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn gzip_stdout_reads() {
    let r = GzipParser.parse(&["-c", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn gzip_suffix_not_file() {
    let r = GzipParser.parse(&["-S", ".z", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn gunzip_default_writes() {
    let r = GunzipParser.parse(&["file.gz"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.gz"]));
}

#[test]
fn bzip2_stdout_reads() {
    let r = Bzip2Parser.parse(&["-c", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn bunzip2_default_writes() {
    let r = Bunzip2Parser.parse(&["file.bz2"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.bz2"]));
}

#[test]
fn xz_default_writes() {
    let r = XzParser.parse(&["file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn xz_stdout_reads() {
    let r = XzParser.parse(&["--stdout", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

#[test]
fn unxz_default_writes() {
    let r = UnxzParser.parse(&["file.xz"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.xz"]));
}

// ── curl / wget ──

#[test]
fn curl_o_writes() {
    let r = CurlParser.parse(&["-o", "out.html", "https://example.com"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/out.html"]));
}

#[test]
fn curl_no_file_access() {
    let r = CurlParser.parse(&["https://example.com"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert!(r.writes.is_empty());
}

#[test]
fn curl_cookie_jar_writes() {
    let r = CurlParser.parse(&["-c", "cookies.txt", "https://example.com"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/cookies.txt"]));
}

#[test]
fn curl_dump_header_writes() {
    let r = CurlParser.parse(&["-D", "headers.txt", "https://example.com"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/headers.txt"]));
}

#[test]
#[allow(non_snake_case)]
fn wget_O_writes() {
    let r = WgetParser.parse(&["-O", "out.html", "https://example.com"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/out.html"]));
}

#[test]
fn wget_input_file_reads() {
    let r = WgetParser.parse(&["-i", "urls.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/urls.txt"]));
}

#[test]
fn wget_no_file_access() {
    let r = WgetParser.parse(&["https://example.com"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert!(r.writes.is_empty());
}

// ── zip / unzip ──

#[test]
fn zip_creates_archive() {
    let r = ZipParser.parse(&["archive.zip", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/a.txt", "/tmp/b.txt"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.zip"]));
}

#[test]
fn zip_recursive() {
    let r = ZipParser.parse(&["-r", "archive.zip", "dir/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.zip"]));
}

#[test]
fn unzip_extracts() {
    let r = UnzipParser.parse(&["archive.zip", "-d", "/dest"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.zip"]));
    assert_eq!(r.writes, writes(&["/dest"]));
}

#[test]
fn unzip_no_dest() {
    let r = UnzipParser.parse(&["archive.zip"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.zip"]));
    assert!(r.writes.is_empty());
}

// ── patch ──

#[test]
fn patch_input_and_original() {
    let r = PatchParser.parse(&["-i", "fix.patch", "file.c"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/fix.patch"]));
    assert_eq!(r.writes, writes(&["/tmp/file.c"]));
}

#[test]
fn patch_output_flag() {
    let r = PatchParser.parse(&["-i", "fix.patch", "-o", "new.c"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/fix.patch"]));
    assert_eq!(r.writes, writes(&["/tmp/new.c"]));
}

#[test]
fn patch_two_positionals() {
    let r = PatchParser.parse(&["file.c", "fix.patch"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/fix.patch"]));
    assert_eq!(r.writes, writes(&["/tmp/file.c"]));
}

// ── split / csplit ──

#[test]
fn split_reads_input() {
    let r = SplitParser.parse(&["-b", "1M", "bigfile.bin"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/bigfile.bin"]));
}

#[test]
fn split_with_prefix() {
    let r = SplitParser.parse(&["bigfile.bin", "chunk_"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/bigfile.bin"]));
}

#[test]
fn csplit_reads_input() {
    let r = CsplitParser.parse(&["file.txt", "/pattern/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ══════════════════════════════════════════════════════════════════════
// SELinux variant tests
// ══════════════════════════════════════════════════════════════════════

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
fn rm_bsd_overwrite_flag() {
    // macOS rm -P (overwrite before deleting)
    let r = RmParser.parse(&["-Prf", "/tmp/sensitive"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/sensitive"]));
}

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
    let r = super::manual_parsers::TarParser.parse(
        &["-xvf", "archive.tar"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.tar"]));
}

#[test]
fn tar_gnu_long_flags() {
    // GNU tar with long flags
    let r = super::manual_parsers::TarParser.parse(
        &["--extract", "--verbose", "--file", "archive.tar", "--directory", "/dest"],
        "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/archive.tar"]));
    assert_eq!(r.writes, writes(&["/dest"]));
}

#[test]
fn tar_gnu_gzip_flag() {
    // GNU tar -z (gzip compression) — should not fail
    let r = super::manual_parsers::TarParser.parse(
        &["-czf", "archive.tar.gz", "dir/"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.tar.gz"]));
}

#[test]
fn tar_gnu_xz_flag() {
    // GNU tar -J (xz compression)
    let r = super::manual_parsers::TarParser.parse(
        &["-cJf", "archive.tar.xz", "dir/"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.tar.xz"]));
}

#[test]
fn tar_gnu_bzip2_flag() {
    // GNU tar -j (bzip2 compression)
    let r = super::manual_parsers::TarParser.parse(
        &["-cjf", "archive.tar.bz2", "src/"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
    assert_eq!(r.writes, writes(&["/tmp/archive.tar.bz2"]));
}

// ── sed BSD vs GNU ──

#[test]
fn sed_bsd_inplace_empty_suffix() {
    // macOS sed requires: sed -i '' 's/foo/bar/' file
    // The '' is the explicit empty suffix, followed by the script
    let r = super::manual_parsers::SedParser.parse(
        &["-i", "s/foo/bar/", "file.txt"], "/tmp",
    ).unwrap();
    // -i is detected, s/foo/bar/ is the script (first non-flag positional), file.txt is the target
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn sed_gnu_extended_regexp() {
    // GNU sed -E (extended regex)
    let r = super::manual_parsers::SedParser.parse(
        &["-E", "s/foo+/bar/", "file.txt"], "/tmp",
    ).unwrap();
    assert_eq!(r.reads, reads(&["/tmp/file.txt"]));
}

// ── grep GNU vs BSD ──

#[test]
fn grep_gnu_include_flag() {
    // GNU grep --include (not on all BSD variants)
    let r = GrepParser.parse(&["-r", "--include", "*.rs", "TODO", "src/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
}

#[test]
fn grep_gnu_exclude_dir() {
    // GNU grep --exclude-dir
    let r = GrepParser.parse(&["-r", "--exclude-dir", ".git", "TODO", "src/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/src/"]));
}

#[test]
fn grep_bsd_null_flag() {
    // Both GNU and BSD support -Z/--null
    let r = GrepParser.parse(&["-rlZ", "pattern", "dir/"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/dir/"]));
}

// ── sort GNU-only flags ──

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
fn gzip_numeric_level() {
    // Both GNU and BSD support -1 through -9
    let r = GzipParser.parse(&["-9", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn gzip_best_fast() {
    // GNU gzip --best / --fast
    let r = GzipParser.parse(&["--best", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

#[test]
fn xz_threads_flag() {
    // GNU xz -T (threads) — value not file
    let r = XzParser.parse(&["-T", "4", "file.txt"], "/tmp").unwrap();
    assert_eq!(r.writes, writes(&["/tmp/file.txt"]));
}

// ── chmod/chown with BSD flags ──

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
