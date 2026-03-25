mod builtins;
mod visitor;

mod visitor_tests;

use crate::file_access::FileAccess;

/// Result of analyzing a Python inline script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonAnalysis {
    /// All file accesses were extracted successfully.
    Analyzed { accesses: Vec<FileAccess> },
    /// The script contains patterns that cannot be statically analyzed.
    Unanalyzable(String),
}

/// Analyze a Python inline script (from `python -c '...'`) and extract file accesses.
///
/// Returns `Analyzed` with a list of file accesses if the script can be fully analyzed,
/// or `Unanalyzable` if it contains patterns we cannot statically verify (exec, eval,
/// subprocess, dynamic paths, etc.).
pub fn analyze_python_script(source: &str, cwd: &str) -> PythonAnalysis {
    use rustpython_parser::Parse;

    let module = match rustpython_ast::ModModule::parse(source, "<inline>") {
        Ok(m) => m,
        Err(e) => return PythonAnalysis::Unanalyzable(format!("Python parse error: {e}")),
    };

    let mut v = visitor::PythonVisitor::new(cwd);
    v.walk_module(&module);
    v.into_result()
}
