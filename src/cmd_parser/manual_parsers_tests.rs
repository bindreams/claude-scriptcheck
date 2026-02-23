use super::manual_parsers::*;
use super::CommandParser;
use pretty_assertions::assert_eq;


fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn w(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

// ── find ──

#[test]
fn find_single_path() {
    let result = FindParser.parse(&["/tmp", "-name", "*.txt"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
    assert!(result.writes.is_empty());
}

#[test]
fn find_multiple_paths() {
    let result = FindParser.parse(&["/tmp", "/var", "-type", "f"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp", "/var"]));
}

#[test]
fn find_relative_path() {
    let result = FindParser.parse(&[".", "-name", "*.rs"], "/home/user").unwrap();
    assert_eq!(result.reads, r(&["/home/user/."]));
}

#[test]
fn find_no_path_expression_first() {
    let result = FindParser.parse(&["-name", "*.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
}

#[test]
fn find_with_negation() {
    let result = FindParser.parse(&["/tmp", "!", "-name", "*.log"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

#[test]
fn find_with_parens() {
    let result = FindParser.parse(&["/tmp", "(", "-name", "*.txt", ")"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

#[test]
fn find_exec() {
    let result = FindParser.parse(
        &["/tmp", "-name", "*.txt", "-exec", "rm", "{}", ";"],
        "/cwd",
    ).unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

#[test]
fn find_maxdepth_before_path() {
    // find -maxdepth 1 . — maxdepth is an expression, so no paths extracted
    let result = FindParser.parse(&["-maxdepth", "1", "."], "/tmp").unwrap();
    assert!(result.reads.is_empty());
}

#[test]
fn find_newer_variant() {
    let result = FindParser.parse(&["/tmp", "-newermt", "2023-01-01"], "/cwd").unwrap();
    assert_eq!(result.reads, r(&["/tmp"]));
}

// ── sed ──

#[test]
fn sed_basic_read() {
    let result = SedParser.parse(&["s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
    assert!(result.writes.is_empty());
}

#[test]
fn sed_inplace_is_write() {
    let result = SedParser.parse(&["-i", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[test]
fn sed_inplace_with_suffix() {
    let result = SedParser.parse(&["-i.bak", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[test]
fn sed_inplace_long_form() {
    let result = SedParser.parse(&["--in-place", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[test]
fn sed_inplace_long_form_with_suffix() {
    let result = SedParser.parse(&["--in-place=.bak", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[test]
fn sed_e_flag_consumes_script() {
    let result = SedParser.parse(&["-e", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[test]
fn sed_multiple_e_flags() {
    let result = SedParser.parse(
        &["-e", "s/foo/bar/", "-e", "s/baz/qux/", "file.txt"],
        "/tmp",
    ).unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[test]
fn sed_f_flag_is_read() {
    let result = SedParser.parse(&["-f", "script.sed", "file.txt"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sed", "/tmp/file.txt"]));
}

#[test]
fn sed_n_flag_is_boolean() {
    let result = SedParser.parse(&["-n", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[test]
fn sed_combined_flags_ni() {
    let result = SedParser.parse(&["-ni", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/file.txt"]));
}

#[test]
fn sed_combined_flags_ne() {
    let result = SedParser.parse(&["-ne", "s/foo/bar/", "file.txt"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/file.txt"]));
}

#[test]
fn sed_script_only_no_files() {
    let result = SedParser.parse(&["s/foo/bar/"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
}

#[test]
fn sed_inplace_multiple_files() {
    let result = SedParser.parse(&["-i", "s/foo/bar/", "a.txt", "b.txt"], "/tmp").unwrap();
    assert_eq!(result.writes, w(&["/tmp/a.txt", "/tmp/b.txt"]));
}

#[test]
fn sed_unknown_flag_fails() {
    let result = SedParser.parse(&["--bogus", "s/foo/bar/", "file.txt"], "/tmp");
    assert!(result.is_err());
}

#[test]
fn sed_double_dash_files() {
    let result = SedParser.parse(&["-e", "s/a/b/", "--", "-weird-file"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/-weird-file"]));
}

// ── tar ──

#[test]
fn tar_create_mode() {
    let result = TarParser.parse(&["-cf", "archive.tar", "dir/"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/dir/"]));
    assert_eq!(result.writes, w(&["/tmp/archive.tar"]));
}

#[test]
fn tar_extract_mode() {
    let result = TarParser.parse(&["-xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
    assert!(result.writes.is_empty());
}

#[test]
fn tar_extract_to_dir() {
    let result = TarParser.parse(&["-xf", "a.tar", "-C", "/dest"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/a.tar"]));
    assert_eq!(result.writes, w(&["/dest"]));
}

#[test]
fn tar_legacy_syntax() {
    let result = TarParser.parse(&["xf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[test]
fn tar_legacy_create() {
    let result = TarParser.parse(&["czf", "archive.tar.gz", "src/"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/src/"]));
    assert_eq!(result.writes, w(&["/tmp/archive.tar.gz"]));
}

#[test]
fn tar_list_mode() {
    let result = TarParser.parse(&["-tf", "archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

#[test]
fn tar_long_flags() {
    let result = TarParser.parse(
        &["--create", "--file", "archive.tar", "--directory", "/src", "."],
        "/tmp",
    ).unwrap();
    assert_eq!(result.reads, r(&["/tmp/."]));
    assert_eq!(result.writes, w(&["/tmp/archive.tar"]));
}

#[test]
fn tar_long_flag_equals() {
    let result = TarParser.parse(&["--extract", "--file=archive.tar"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/archive.tar"]));
}

// ── dd ──

#[test]
fn dd_basic() {
    let result = DdParser.parse(&["if=input.bin", "of=output.bin", "bs=4096"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/input.bin"]));
    assert_eq!(result.writes, w(&["/tmp/output.bin"]));
}

#[test]
fn dd_only_input() {
    let result = DdParser.parse(&["if=/dev/urandom", "bs=1M", "count=1"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/dev/urandom"]));
    assert!(result.writes.is_empty());
}

#[test]
fn dd_only_output() {
    let result = DdParser.parse(&["of=/tmp/zeros", "bs=1M", "count=100"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.writes, w(&["/tmp/zeros"]));
}

#[test]
fn dd_unknown_arg_fails() {
    let result = DdParser.parse(&["if=input", "badarg"], "/tmp");
    assert!(result.is_err());
}

// ── shell (bash/sh/zsh/dash) ──

#[test]
fn shell_inline_c() {
    let result = ShellParser.parse(&["-c", "echo hello"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn shell_combined_xc() {
    let result = ShellParser.parse(&["-xc", "echo hello"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn shell_c_with_dollar_zero() {
    let result = ShellParser.parse(&["-c", "echo $0", "myname", "arg1"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn shell_script_file() {
    let result = ShellParser.parse(&["script.sh"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sh"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn shell_script_file_with_flags() {
    let result = ShellParser.parse(&["-x", "script.sh", "arg1"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sh"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn shell_stdin_mode() {
    let result = ShellParser.parse(&["-s"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn shell_no_args() {
    let result = ShellParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn shell_login_script() {
    let result = ShellParser.parse(&["-l", "script.sh"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sh"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn shell_o_option_skipped() {
    let result = ShellParser.parse(&["-o", "pipefail", "-c", "echo hello"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(3));
}

// ── python ──

#[test]
fn python_inline_c() {
    let result = PythonParser.parse(&["-c", "print('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn python_combined_bc() {
    let result = PythonParser.parse(&["-Bc", "print('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn python_script_file() {
    let result = PythonParser.parse(&["script.py"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.py"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn python_script_file_with_args() {
    let result = PythonParser.parse(&["script.py", "--verbose"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.py"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn python_module_mode() {
    let result = PythonParser.parse(&["-m", "pytest"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn python_stdin() {
    let result = PythonParser.parse(&["-"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn python_no_args() {
    let result = PythonParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn python_w_flag_value_consumed() {
    let result = PythonParser.parse(&["-W", "ignore", "-c", "print(1)"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(3));
}

// ── ruby ──

#[test]
fn ruby_inline_e() {
    let result = RubyParser.parse(&["-e", "puts 'hi'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn ruby_combined_ne() {
    let result = RubyParser.parse(&["-ne", "puts $_"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn ruby_script_file() {
    let result = RubyParser.parse(&["script.rb"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.rb"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn ruby_no_args() {
    let result = RubyParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

// ── node ──

#[test]
fn node_inline_e() {
    let result = NodeParser.parse(&["-e", "console.log('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn node_inline_eval_long() {
    let result = NodeParser.parse(&["--eval", "console.log('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn node_inline_eval_equals() {
    let result = NodeParser.parse(&["--eval=console.log('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(0));
}

#[test]
fn node_inline_print() {
    let result = NodeParser.parse(&["-p", "1+1"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn node_script_file() {
    let result = NodeParser.parse(&["app.js"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/app.js"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn node_check_flag_is_not_inline() {
    // node -c is --check (syntax check), NOT inline script
    let result = NodeParser.parse(&["-c", "app.js"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/app.js"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn node_no_args() {
    let result = NodeParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

// ── perl ──

#[test]
fn perl_inline_e() {
    let result = PerlParser.parse(&["-e", "print 'hi'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn perl_inline_capital_e() {
    let result = PerlParser.parse(&["-E", "say 'hi'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn perl_combined_ne() {
    let result = PerlParser.parse(&["-ne", "print"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[test]
fn perl_embedded_script() {
    // perl -e'print 1' — script attached to flag
    let result = PerlParser.parse(&["-e'print 1'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(0));
}

#[test]
fn perl_script_file() {
    let result = PerlParser.parse(&["script.pl"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.pl"]));
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn perl_no_args() {
    let result = PerlParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[test]
fn perl_i_flag_value_consumed() {
    let result = PerlParser.parse(&["-I", "/usr/lib", "-e", "print 1"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(3));
}
