use super::script_runners::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn shell_inline_c() {
    let result = ShellParser.parse(&["-c", "echo hello"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn shell_combined_xc() {
    let result = ShellParser.parse(&["-xc", "echo hello"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn shell_c_with_dollar_zero() {
    let result = ShellParser.parse(&["-c", "echo $0", "myname", "arg1"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn shell_script_file() {
    let result = ShellParser.parse(&["script.sh"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sh"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn shell_script_file_with_flags() {
    let result = ShellParser.parse(&["-x", "script.sh", "arg1"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sh"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn shell_stdin_mode() {
    let result = ShellParser.parse(&["-s"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn shell_no_args() {
    let result = ShellParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn shell_login_script() {
    let result = ShellParser.parse(&["-l", "script.sh"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.sh"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn shell_o_option_skipped() {
    let result = ShellParser.parse(&["-o", "pipefail", "-c", "echo hello"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(3));
}


#[skuld::test]
fn python_inline_c() {
    let result = PythonParser.parse(&["-c", "print('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn python_combined_bc() {
    let result = PythonParser.parse(&["-Bc", "print('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn python_script_file() {
    let result = PythonParser.parse(&["script.py"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.py"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn python_script_file_with_args() {
    let result = PythonParser.parse(&["script.py", "--verbose"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.py"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn python_module_mode() {
    let result = PythonParser.parse(&["-m", "pytest"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn python_stdin() {
    let result = PythonParser.parse(&["-"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn python_no_args() {
    let result = PythonParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn python_w_flag_value_consumed() {
    let result = PythonParser.parse(&["-W", "ignore", "-c", "print(1)"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(3));
}


#[skuld::test]
fn ruby_inline_e() {
    let result = RubyParser.parse(&["-e", "puts 'hi'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn ruby_combined_ne() {
    let result = RubyParser.parse(&["-ne", "puts $_"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn ruby_script_file() {
    let result = RubyParser.parse(&["script.rb"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.rb"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn ruby_no_args() {
    let result = RubyParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}


#[skuld::test]
fn node_inline_e() {
    let result = NodeParser.parse(&["-e", "console.log('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn node_inline_eval_long() {
    let result = NodeParser.parse(&["--eval", "console.log('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn node_inline_eval_equals() {
    let result = NodeParser.parse(&["--eval=console.log('hi')"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(0));
}

#[skuld::test]
fn node_inline_print() {
    let result = NodeParser.parse(&["-p", "1+1"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn node_script_file() {
    let result = NodeParser.parse(&["app.js"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/app.js"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn node_check_flag_is_not_inline() {
    // node -c is --check (syntax check), NOT inline script
    let result = NodeParser.parse(&["-c", "app.js"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/app.js"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn node_no_args() {
    let result = NodeParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}


#[skuld::test]
fn perl_inline_e() {
    let result = PerlParser.parse(&["-e", "print 'hi'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn perl_inline_capital_e() {
    let result = PerlParser.parse(&["-E", "say 'hi'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn perl_combined_ne() {
    let result = PerlParser.parse(&["-ne", "print"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(1));
}

#[skuld::test]
fn perl_embedded_script() {
    // perl -e'print 1' — script attached to flag
    let result = PerlParser.parse(&["-e'print 1'"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(0));
}

#[skuld::test]
fn perl_script_file() {
    let result = PerlParser.parse(&["script.pl"], "/tmp").unwrap();
    assert_eq!(result.reads, r(&["/tmp/script.pl"]));
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn perl_no_args() {
    let result = PerlParser.parse(&[], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, None);
}

#[skuld::test]
fn perl_i_flag_value_consumed() {
    let result = PerlParser.parse(&["-I", "/usr/lib", "-e", "print 1"], "/tmp").unwrap();
    assert!(result.reads.is_empty());
    assert_eq!(result.inline_script_start, Some(3));
}
