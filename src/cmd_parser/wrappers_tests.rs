#[cfg(test)]
mod tests {
    use crate::cmd_parser::wrappers::UvParser;
    use crate::cmd_parser::CommandParser;

    #[test]
    fn uv_run_python_c_sets_inline_script() {
        let result = UvParser
            .parse(&["run", "python", "-c", "print(1)"], "/tmp")
            .unwrap();
        // inline_script_start should point to the "-c" script text
        // Within the uv parser: inner args = ["-c", "print(1)"], script_start = 1
        // Adjusted by consumed_prefix (run=1 + python=1 = 2): 1 + 2 = 3
        assert_eq!(result.inline_script_start, Some(3));
        assert_eq!(result.effective_cmd_name.as_deref(), Some("python"));
    }

    #[test]
    fn uv_run_with_flag_python_c() {
        let result = UvParser
            .parse(&["run", "--with", "requests", "python", "-c", "print(1)"], "/tmp")
            .unwrap();
        assert_eq!(result.inline_script_start, Some(5));
        assert_eq!(result.effective_cmd_name.as_deref(), Some("python"));
    }

    #[test]
    fn uv_run_separator_python_c() {
        let result = UvParser
            .parse(&["run", "--", "python", "-c", "print(1)"], "/tmp")
            .unwrap();
        assert_eq!(result.inline_script_start, Some(4));
        assert_eq!(result.effective_cmd_name.as_deref(), Some("python"));
    }

    #[test]
    fn uv_run_script_py() {
        let result = UvParser
            .parse(&["run", "script.py"], "/tmp")
            .unwrap();
        assert_eq!(result.reads, vec!["/tmp/script.py"]);
        assert_eq!(result.effective_cmd_name.as_deref(), Some("script.py"));
    }

    #[test]
    fn uv_run_unknown_tool() {
        let result = UvParser
            .parse(&["run", "pytest", "-v"], "/tmp")
            .unwrap();
        assert!(result.reads.is_empty());
        assert!(result.writes.is_empty());
        assert_eq!(result.effective_cmd_name.as_deref(), Some("pytest"));
    }

    #[test]
    fn uv_run_unknown_flag_errors() {
        let result = UvParser.parse(&["run", "--unknown", "python"], "/tmp");
        assert!(result.is_err());
    }

    #[test]
    fn uv_run_trailing_value_flag_errors() {
        let result = UvParser.parse(&["run", "--with"], "/tmp");
        assert!(result.is_err());
    }

    #[test]
    fn uv_run_no_command() {
        let result = UvParser.parse(&["run"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert!(result.writes.is_empty());
    }

    #[test]
    fn uv_non_run_subcommand_returns_empty() {
        let result = UvParser.parse(&["tool", "run", "pytest"], "/tmp").unwrap();
        assert!(result.reads.is_empty());
        assert_eq!(result.effective_cmd_name, None);
    }

    #[test]
    fn uv_run_with_equals_form() {
        let result = UvParser
            .parse(&["run", "--with=requests", "python", "-c", "print(1)"], "/tmp")
            .unwrap();
        assert_eq!(result.inline_script_start, Some(4));
        assert_eq!(result.effective_cmd_name.as_deref(), Some("python"));
    }

    #[test]
    fn uv_run_python_versioned() {
        let result = UvParser
            .parse(&["run", "python3.12", "-c", "print(1)"], "/tmp")
            .unwrap();
        assert_eq!(result.effective_cmd_name.as_deref(), Some("python3.12"));
        assert_eq!(result.inline_script_start, Some(3));
    }
}
