use thaum::ast::{Argument, Atom, Fragment, Word};

/// Attempt to extract a fully-static string from a Word.
/// Returns None if any fragment is dynamic (variable, command sub, glob, etc.).
pub fn try_literal(word: &Word) -> Option<String> {
    let mut result = String::new();
    for fragment in &word.parts {
        try_literal_fragment(fragment, &mut result)?;
    }
    Some(result)
}

fn try_literal_fragment(fragment: &Fragment, result: &mut String) -> Option<()> {
    match fragment {
        Fragment::Literal(s) => result.push_str(s),
        Fragment::SingleQuoted(s) => result.push_str(s),
        Fragment::DoubleQuoted(inner) => {
            for f in inner {
                try_literal_fragment(f, result)?;
            }
        }
        Fragment::TildePrefix(user) => {
            result.push('~');
            result.push_str(user);
        }
        Fragment::BashAnsiCQuoted(s) => result.push_str(s),
        // Everything else is dynamic — cannot resolve statically
        Fragment::Parameter(_)
        | Fragment::CommandSubstitution(_)
        | Fragment::ArithmeticExpansion(_)
        | Fragment::Glob(_)
        | Fragment::BashExtGlob { .. }
        | Fragment::BashBraceExpansion(_)
        | Fragment::BashLocaleQuoted(_) => return None,
    }
    Some(())
}

/// Extract a static literal from an Argument node.
pub fn try_argument_literal(arg: &Argument) -> Option<String> {
    match arg {
        Argument::Word(w) => try_literal(w),
        Argument::Atom(Atom::BashProcessSubstitution { .. }) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_first_arg(input: &str) -> Argument {
        let prog = thaum::parse_with(input, thaum::Dialect::Bash).unwrap();
        let stmt = prog.statements.into_iter().next().unwrap();
        match stmt.expression {
            thaum::ast::Expression::Command(cmd) => cmd.arguments.into_iter().next().unwrap(),
            _ => panic!("expected Command"),
        }
    }

    fn parse_arg_at(input: &str, idx: usize) -> Argument {
        let prog = thaum::parse_with(input, thaum::Dialect::Bash).unwrap();
        let stmt = prog.statements.into_iter().next().unwrap();
        match stmt.expression {
            thaum::ast::Expression::Command(cmd) => {
                cmd.arguments.into_iter().nth(idx).unwrap()
            }
            _ => panic!("expected Command"),
        }
    }

    #[test]
    fn literal_word() {
        let arg = parse_first_arg("hello");
        assert_eq!(try_argument_literal(&arg), Some("hello".to_string()));
    }

    #[test]
    fn single_quoted() {
        let arg = parse_arg_at("echo 'hello world'", 1);
        assert_eq!(try_argument_literal(&arg), Some("hello world".to_string()));
    }

    #[test]
    fn double_quoted_literal() {
        let arg = parse_arg_at("echo \"hello\"", 1);
        assert_eq!(try_argument_literal(&arg), Some("hello".to_string()));
    }

    #[test]
    fn double_quoted_with_variable() {
        let arg = parse_arg_at("echo \"$HOME/foo\"", 1);
        assert_eq!(try_argument_literal(&arg), None);
    }

    #[test]
    fn tilde_prefix() {
        let arg = parse_arg_at("cat ~/file.txt", 1);
        assert_eq!(try_argument_literal(&arg), Some("~/file.txt".to_string()));
    }

    #[test]
    fn variable_expansion() {
        let arg = parse_arg_at("echo $HOME", 1);
        assert_eq!(try_argument_literal(&arg), None);
    }

    #[test]
    fn glob_star() {
        let arg = parse_arg_at("ls *.txt", 1);
        assert_eq!(try_argument_literal(&arg), None);
    }

    #[test]
    fn command_substitution() {
        let arg = parse_arg_at("echo $(date)", 1);
        assert_eq!(try_argument_literal(&arg), None);
    }
}
