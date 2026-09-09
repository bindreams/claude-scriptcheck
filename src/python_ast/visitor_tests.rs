#[cfg(test)]
mod tests {
    use crate::file_access::{AccessKind, FileAccess};
    use crate::python_ast::{analyze_python_script, PythonAnalysis};

    fn analyzed(source: &str, cwd: &str) -> Vec<FileAccess> {
        match analyze_python_script(source, cwd) {
            PythonAnalysis::Analyzed { accesses } => accesses,
            PythonAnalysis::Unanalyzable(reason) => {
                panic!("expected Analyzed, got Unanalyzable: {reason}")
            }
        }
    }

    fn unanalyzable(source: &str) -> String {
        match analyze_python_script(source, "/tmp") {
            PythonAnalysis::Unanalyzable(reason) => reason,
            PythonAnalysis::Analyzed { accesses } => {
                panic!("expected Unanalyzable, got Analyzed with {accesses:?}")
            }
        }
    }

    fn read(path: &str) -> FileAccess {
        FileAccess {
            path: path.to_string(),
            kind: AccessKind::Read,
        }
    }

    fn write(path: &str) -> FileAccess {
        FileAccess {
            path: path.to_string(),
            kind: AccessKind::Write,
        }
    }

    // Parse failures ==================================================================================================

    #[test]
    fn parse_error_is_unanalyzable() {
        let reason = unanalyzable("def (broken");
        assert!(reason.contains("parse error"), "reason: {reason}");
    }

    // Empty / pure computation ========================================================================================

    #[test]
    fn empty_script() {
        assert_eq!(analyzed("", "/tmp"), vec![]);
    }

    #[test]
    fn pure_computation() {
        assert_eq!(analyzed("x = 1 + 2\nprint(x)", "/tmp"), vec![]);
    }

    #[test]
    fn import_and_compute() {
        assert_eq!(
            analyzed("import json\ndata = json.loads('{}')", "/tmp"),
            vec![]
        );
    }

    // open() reads ====================================================================================================

    #[test]
    fn open_default_mode_is_read() {
        assert_eq!(analyzed("open('/tmp/a')", "/tmp"), vec![read("/tmp/a")]);
    }

    #[test]
    fn open_explicit_read_mode() {
        assert_eq!(
            analyzed("open('/tmp/a', 'r')", "/tmp"),
            vec![read("/tmp/a")]
        );
    }

    #[test]
    fn open_read_binary() {
        assert_eq!(
            analyzed("open('/tmp/a', 'rb')", "/tmp"),
            vec![read("/tmp/a")]
        );
    }

    #[test]
    fn open_read_text() {
        assert_eq!(
            analyzed("open('/tmp/a', 'rt')", "/tmp"),
            vec![read("/tmp/a")]
        );
    }

    // open() writes ===================================================================================================

    #[test]
    fn open_write_mode() {
        assert_eq!(
            analyzed("open('/tmp/a', 'w')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    #[test]
    fn open_write_binary() {
        assert_eq!(
            analyzed("open('/tmp/a', 'wb')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    #[test]
    fn open_append_mode() {
        assert_eq!(
            analyzed("open('/tmp/a', 'a')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    #[test]
    fn open_exclusive_create() {
        assert_eq!(
            analyzed("open('/tmp/a', 'x')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    #[test]
    fn open_read_write_plus() {
        assert_eq!(
            analyzed("open('/tmp/a', 'r+')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    #[test]
    fn open_write_plus() {
        assert_eq!(
            analyzed("open('/tmp/a', 'w+')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    #[test]
    fn open_append_plus() {
        assert_eq!(
            analyzed("open('/tmp/a', 'a+')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    // open() with keyword mode ========================================================================================

    #[test]
    fn open_keyword_mode() {
        assert_eq!(
            analyzed("open('/tmp/a', mode='w')", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    // Dynamic path / mode =============================================================================================

    #[test]
    fn open_dynamic_path() {
        unanalyzable("open(some_var)");
    }

    #[test]
    fn open_dynamic_mode() {
        unanalyzable("open('/tmp/a', mode=some_var)");
    }

    #[test]
    fn open_fstring_path() {
        unanalyzable("open(f'/tmp/{name}')");
    }

    // with statement ==================================================================================================

    #[test]
    fn with_open_read() {
        assert_eq!(
            analyzed("with open('/tmp/a') as f:\n    data = f.read()", "/tmp"),
            vec![read("/tmp/a")]
        );
    }

    #[test]
    fn with_open_write() {
        assert_eq!(
            analyzed(
                "with open('/tmp/a', 'w') as f:\n    f.write('hello')",
                "/tmp"
            ),
            vec![write("/tmp/a")]
        );
    }

    // Nested open() in call arguments =================================================================================

    #[test]
    fn open_nested_in_json_dump() {
        assert_eq!(
            analyzed("import json\njson.dump(data, open('/tmp/x', 'w'))", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    #[test]
    fn open_nested_in_print_file_kwarg() {
        assert_eq!(
            analyzed("print('hi', file=open('/tmp/x', 'w'))", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    #[test]
    fn open_nested_in_json_load() {
        assert_eq!(
            analyzed("import json\njson.load(open('/tmp/x'))", "/tmp"),
            vec![read("/tmp/x")]
        );
    }

    // Multiple open() calls ===========================================================================================

    #[test]
    fn multiple_opens() {
        assert_eq!(
            analyzed("open('/tmp/a')\nopen('/tmp/b', 'w')", "/tmp"),
            vec![read("/tmp/a"), write("/tmp/b")]
        );
    }

    // Relative paths ==================================================================================================

    #[test]
    fn relative_path_resolved_against_cwd() {
        assert_eq!(
            analyzed("open('data.txt')", "/home/user/project"),
            vec![read("/home/user/project/data.txt")]
        );
    }

    // Unsafe builtins =================================================================================================

    #[test]
    fn exec_is_unanalyzable() {
        unanalyzable("exec('code')");
    }

    #[test]
    fn eval_is_unanalyzable() {
        unanalyzable("eval('1 + 2')");
    }

    #[test]
    fn compile_is_unanalyzable() {
        unanalyzable("compile('code', '<string>', 'exec')");
    }

    #[test]
    fn dunder_import_is_unanalyzable() {
        unanalyzable("__import__('os')");
    }

    // Unsafe module imports ===========================================================================================

    #[test]
    fn import_subprocess_is_unanalyzable() {
        unanalyzable("import subprocess");
    }

    #[test]
    fn import_subprocess_as_alias() {
        unanalyzable("import subprocess as sp");
    }

    #[test]
    fn from_subprocess_import() {
        unanalyzable("from subprocess import run");
    }

    #[test]
    fn import_ctypes_is_unanalyzable() {
        unanalyzable("import ctypes");
    }

    #[test]
    fn import_socket_is_unanalyzable() {
        unanalyzable("import socket");
    }

    #[test]
    fn import_importlib_is_unanalyzable() {
        unanalyzable("import importlib");
    }

    // Unsafe qualified calls ==========================================================================================

    #[test]
    fn os_system_is_unanalyzable() {
        unanalyzable("import os\nos.system('ls')");
    }

    #[test]
    fn os_popen_is_unanalyzable() {
        unanalyzable("import os\nos.popen('ls')");
    }

    #[test]
    fn os_execl_is_unanalyzable() {
        unanalyzable("import os\nos.execl('/bin/sh', 'sh')");
    }

    #[test]
    fn from_os_import_system() {
        unanalyzable("from os import system\nsystem('ls')");
    }

    // Star imports ====================================================================================================

    #[test]
    fn star_import_is_unanalyzable() {
        unanalyzable("from os import *");
    }

    // Builtin shadowing ===============================================================================================

    #[test]
    fn open_shadowed_by_assignment() {
        // When open is reassigned, it's no longer the builtin -- calls to it are just unknown
        assert_eq!(
            analyzed("open = lambda f: None\nopen('/tmp/x')", "/tmp"),
            vec![]
        );
    }

    #[test]
    fn open_shadowed_by_def() {
        assert_eq!(
            analyzed("def open(x):\n    pass\nopen('/tmp/x')", "/tmp"),
            vec![]
        );
    }

    #[test]
    fn open_shadowed_by_import() {
        // from mylib import open -- shadows the builtin
        assert_eq!(
            analyzed("from mylib import open\nopen('/tmp/x')", "/tmp"),
            vec![]
        );
    }

    #[test]
    fn exec_shadowed_is_not_unsafe() {
        // If exec is shadowed, it's not the unsafe builtin anymore
        assert_eq!(analyzed("exec = print\nexec('hello')", "/tmp"), vec![]);
    }

    // builtins.open ===================================================================================================

    #[test]
    fn builtins_open() {
        assert_eq!(
            analyzed("import builtins\nbuiltins.open('/tmp/x')", "/tmp"),
            vec![read("/tmp/x")]
        );
    }

    #[test]
    fn builtins_open_write() {
        assert_eq!(
            analyzed("import builtins\nbuiltins.open('/tmp/x', 'w')", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    // io.open =========================================================================================================

    #[test]
    fn io_open_read() {
        assert_eq!(
            analyzed("import io\nio.open('/tmp/x')", "/tmp"),
            vec![read("/tmp/x")]
        );
    }

    #[test]
    fn io_open_write() {
        assert_eq!(
            analyzed("import io\nio.open('/tmp/x', 'w')", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    // Stdin pipeline (no file access) =================================================================================

    #[test]
    fn sys_stdin_no_file_access() {
        assert_eq!(
            analyzed(
                "import sys, json\ndata = json.load(sys.stdin)\nprint(data)",
                "/tmp"
            ),
            vec![]
        );
    }

    // Control flow ====================================================================================================

    #[test]
    fn if_branch_both_analyzed() {
        assert_eq!(
            analyzed(
                "if True:\n    open('/tmp/a')\nelse:\n    open('/tmp/b', 'w')",
                "/tmp"
            ),
            vec![read("/tmp/a"), write("/tmp/b")]
        );
    }

    #[test]
    fn for_loop_body_analyzed() {
        // Static file access inside a loop is still detected
        assert_eq!(
            analyzed("for _ in range(3):\n    open('/tmp/a')", "/tmp"),
            vec![read("/tmp/a")]
        );
    }

    // Nested function definitions =====================================================================================

    #[test]
    fn function_body_analyzed_conservatively() {
        assert_eq!(
            analyzed("def f():\n    open('/tmp/a', 'w')\n", "/tmp"),
            vec![write("/tmp/a")]
        );
    }

    // open() with no args (will fail at runtime, but not a file access) ===============================================

    #[test]
    fn open_no_args() {
        assert_eq!(analyzed("open()", "/tmp"), vec![]);
    }

    // Safe modules ====================================================================================================

    #[test]
    fn import_os_is_safe() {
        // Importing os alone is safe; it's os.system() etc. that are unsafe
        assert_eq!(analyzed("import os\nprint(os.getcwd())", "/tmp"), vec![]);
    }

    #[test]
    fn import_json_is_safe() {
        assert_eq!(analyzed("import json\njson.loads('{}')", "/tmp"), vec![]);
    }

    #[test]
    fn import_sys_is_safe() {
        assert_eq!(analyzed("import sys\nprint(sys.argv)", "/tmp"), vec![]);
    }

    // Aliased unsafe import then call =================================================================================

    #[test]
    fn aliased_os_system() {
        unanalyzable("import os as operating_system\noperating_system.system('ls')");
    }

    // Try/except with open ============================================================================================

    #[test]
    fn try_except_with_open() {
        assert_eq!(
            analyzed(
                "try:\n    open('/tmp/a')\nexcept:\n    open('/tmp/b', 'w')",
                "/tmp"
            ),
            vec![read("/tmp/a"), write("/tmp/b")]
        );
    }

    // os file-mutating functions ======================================================================================

    #[test]
    fn os_remove_extracts_write() {
        assert_eq!(
            analyzed("import os\nos.remove('/tmp/x')", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    #[test]
    fn os_unlink_extracts_write() {
        assert_eq!(
            analyzed("import os\nos.unlink('/tmp/x')", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    #[test]
    fn os_rename_extracts_read_and_write() {
        assert_eq!(
            analyzed("import os\nos.rename('/tmp/a', '/tmp/b')", "/tmp"),
            vec![read("/tmp/a"), write("/tmp/b")]
        );
    }

    #[test]
    fn os_makedirs_extracts_write() {
        assert_eq!(
            analyzed("import os\nos.makedirs('/tmp/dir')", "/tmp"),
            vec![write("/tmp/dir")]
        );
    }

    #[test]
    fn os_mkdir_extracts_write() {
        assert_eq!(
            analyzed("import os\nos.mkdir('/tmp/dir')", "/tmp"),
            vec![write("/tmp/dir")]
        );
    }

    #[test]
    fn os_open_is_unanalyzable() {
        unanalyzable("import os\nos.open('/tmp/x', os.O_WRONLY)");
    }

    #[test]
    fn from_os_import_remove_extracts_write() {
        assert_eq!(
            analyzed("from os import remove\nremove('/tmp/x')", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    #[test]
    fn os_makedirs_dynamic_path_is_unanalyzable() {
        unanalyzable("import os\nos.makedirs(some_var)");
    }

    #[test]
    fn os_truncate_extracts_write() {
        assert_eq!(
            analyzed("import os\nos.truncate('/tmp/f', 100)", "/tmp"),
            vec![write("/tmp/f")]
        );
    }

    #[test]
    fn os_symlink_extracts_read_and_write() {
        assert_eq!(
            analyzed("import os\nos.symlink('/tmp/target', '/tmp/link')", "/tmp"),
            vec![read("/tmp/target"), write("/tmp/link")]
        );
    }

    #[test]
    fn os_makedirs_keyword_arg() {
        assert_eq!(
            analyzed(
                "import os\nos.makedirs(name='/tmp/dir', exist_ok=True)",
                "/tmp"
            ),
            vec![write("/tmp/dir")]
        );
    }

    #[test]
    fn os_rename_keyword_args() {
        assert_eq!(
            analyzed("import os\nos.rename(src='/tmp/a', dst='/tmp/b')", "/tmp"),
            vec![read("/tmp/a"), write("/tmp/b")]
        );
    }

    // shutil is unsafe module =========================================================================================

    #[test]
    fn import_shutil_is_unanalyzable() {
        unanalyzable("import shutil");
    }

    #[test]
    fn from_shutil_import_copy() {
        unanalyzable("from shutil import copy");
    }

    // urllib.request is unsafe submodule ==============================================================================

    #[test]
    fn import_urllib_request_is_unanalyzable() {
        unanalyzable("import urllib.request");
    }

    #[test]
    fn import_urllib_parse_is_safe() {
        assert_eq!(analyzed("import urllib.parse", "/tmp"), vec![]);
    }

    #[test]
    fn from_urllib_request_import_is_unanalyzable() {
        unanalyzable("from urllib.request import urlopen");
    }

    #[test]
    fn from_urllib_parse_import_is_safe() {
        assert_eq!(
            analyzed("from urllib.parse import urlparse", "/tmp"),
            vec![]
        );
    }

    #[test]
    fn from_urllib_import_request_then_urlopen_is_unanalyzable() {
        unanalyzable("from urllib import request\nrequest.urlopen('http://x')");
    }

    // open() with splat args ==========================================================================================

    #[test]
    fn open_with_star_args() {
        unanalyzable("open(*args)");
    }

    #[test]
    fn open_with_double_star_kwargs() {
        unanalyzable("open(**kwargs)");
    }

    // from builtins import open =======================================================================================

    #[test]
    fn from_builtins_import_open() {
        assert_eq!(
            analyzed("from builtins import open\nopen('/tmp/x')", "/tmp"),
            vec![read("/tmp/x")]
        );
    }

    #[test]
    fn from_builtins_import_open_write() {
        assert_eq!(
            analyzed("from builtins import open\nopen('/tmp/x', 'w')", "/tmp"),
            vec![write("/tmp/x")]
        );
    }

    // Builtin shadowing in various binding contexts ===================================================================

    #[test]
    fn open_shadowed_by_for_target() {
        assert_eq!(
            analyzed("for open in [1, 2]:\n    open('/tmp/x')", "/tmp"),
            vec![]
        );
    }

    #[test]
    fn open_shadowed_by_with_as() {
        assert_eq!(
            analyzed("with something() as open:\n    open('/tmp/x')", "/tmp"),
            vec![]
        );
    }

    #[test]
    fn open_shadowed_by_except_as() {
        assert_eq!(
            analyzed(
                "try:\n    pass\nexcept Exception as open:\n    open('/tmp/x')",
                "/tmp"
            ),
            vec![]
        );
    }

    #[test]
    fn open_shadowed_by_comprehension_target() {
        assert_eq!(
            analyzed("[open('/tmp/x') for open in [1, 2]]", "/tmp"),
            vec![]
        );
    }

    // Slice sub-expressions are walked ================================================================================

    #[test]
    fn open_in_slice_lower() {
        // Pathological but possible: open() inside a slice expression
        assert_eq!(
            analyzed("x = [1,2,3]\ny = x[open('/tmp/a'):2]", "/tmp"),
            vec![read("/tmp/a")]
        );
    }
}
