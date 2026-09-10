//! Classification of environment-variable names in a command's assignment prefix.
//!
//! The checker models a command from its argv. The environment is a second
//! input channel that argv does not describe, and an assignment to the wrong
//! variable turns a read-only invocation into an arbitrary execution:
//! `GIT_EXTERNAL_DIFF=./evil.sh git diff` runs `evil.sh`.
//!
//! The list here is of variables that are **inert**, not of variables that are
//! dangerous. Enumerating dangerous names cannot terminate — `LD_PRELOAD` and
//! `DYLD_INSERT_LIBRARIES` subvert any dynamically linked command, so no
//! reasoning about a particular command bounds the set. Inverting the default
//! bounds it from the other side, and it fails in the safe direction: a
//! variable missing from this list costs one prompt, a variable wrongly on it
//! is a hole.
//!
//! # Inertness is conditional on argv, not a property of the variable
//!
//! **This is the contract's sharpest edge and it is easy to miss.** A variable
//! is inert only *given the command it is attached to*. `LC_ALL` genuinely
//! cannot change what a program executes — until argv names it as a config
//! source, at which point it can:
//!
//! ```text
//! LC_ALL=./evil.sh git --config-env=diff.external=LC_ALL diff
//! ```
//!
//! git reads the config value out of the named variable, so the inert list is
//! what makes this reachable with no rules. The defence is not a better list —
//! no list survives an argv that can name any variable — it is that the
//! *option* which turns a variable into a config source must itself demand a
//! `Bash(...)` rule. `git`'s `-c` and `--config-env` both do.
//!
//! So when adding an entry here, the question is not only "can this variable
//! change what a command does" but "is there an option, anywhere, that makes
//! this variable's value into code". If a parser learns a new option of that
//! shape, it belongs in that parser's guardrail, not in a subtraction from
//! this list.
//!
//! # The criterion for adding an entry
//!
//! A variable is inert only if it can neither
//!
//! a. name, or influence the resolution of, a program the command executes,
//! b. name a file the command reads as configuration or writes, nor
//! c. change the command's view of the filesystem — home, cwd, temp, search
//!    roots.
//!
//! Presentation, locale, verbosity and buffering qualify. Anything naming a
//! path or a program does not. Add an entry when the criterion is met and
//! there is evidence the variable is used in practice; do not add one to
//! "complete a family".
//!
//! # Names that look like they belong here and do not
//!
//! - `LOCPATH`, `NLSPATH` — name directories, so (c). This is why the inert
//!   locale entries are the `LC_` namespace and `LANG`/`LANGUAGE` only.
//! - `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP` — a module search root, an
//!   installation root, and a script Python executes at startup: (a) and (c).
//!   This is why `PYTHON` is **not** prefix-matched while `LC_` is.
//! - `TERM`, `TERMINFO`, `TERMINFO_DIRS` — select and locate a terminfo entry
//!   the process parses, so (b) at least.
//! - `RUSTFLAGS`, `RUSTC_WRAPPER` — name a linker and a program, so (a).

/// Environment variable names that are inert on their own.
///
/// Compared case-sensitively: environment variable names are case-sensitive
/// for the purpose of what a child process reads, and a case-insensitive
/// match would make `lc_all` inert.
const INERT: &[&str] = &[
    // Locale. `LC_` is handled by prefix below; these are the two spellings
    // outside that namespace.
    "LANG",
    "LANGUAGE",
    // Colour and terminal geometry — presentation only.
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLUMNS",
    "LINES",
    // Buffering and bytecode caching. Not the `PYTHON` namespace at large;
    // see the module docs.
    "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE",
    // Diagnostics verbosity.
    "RUST_BACKTRACE",
    "RUST_LOG",
    // Environment self-description.
    "CI",
];

/// The one prefix-matched namespace. POSIX reserves `LC_*` for locale
/// categories, and `LOCPATH` / `NLSPATH` — which do name paths — are outside
/// it by construction.
///
/// **Named residual, accepted deliberately.** This is not quite "closed": a
/// locale *name* containing a slash is implementation-defined under POSIX, and
/// glibc resolves locale data through files, so `LANG` and `LC_*` do influence
/// which files a process opens. They are kept inert because the surface they
/// reach is locale-data parsing rather than execution. `TZ` is *not* inert for
/// the mirror-image reason: `TZ=:/path` names a file, so it fails criterion
/// (b).
const INERT_PREFIX: &str = "LC_";

/// True when an assignment to `name` cannot change what a command does *on
/// its own*, per the criterion in the module documentation.
///
/// Not an absolute property: an option such as `git --config-env=<key>=<name>`
/// turns any variable into a config value, and defending that is the option's
/// guardrail, not this list. See the module docs.
///
/// Kept `pub` because the exported-assignment work (#64) classifies the same
/// names; do not narrow it to `pub(crate)`.
pub fn is_inert(name: &str) -> bool {
    name.starts_with(INERT_PREFIX) || INERT.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_all(names: &[&str], expected: bool) {
        for name in names {
            assert_eq!(is_inert(name), expected, "is_inert({name:?})");
        }
    }

    #[test]
    fn inert_locale_family() {
        assert_all(
            &["LANG", "LANGUAGE", "LC_ALL", "LC_COLLATE", "LC_CTYPE"],
            true,
        );
    }

    #[test]
    fn inert_presentation_and_verbosity() {
        assert_all(
            &[
                "NO_COLOR",
                "FORCE_COLOR",
                "COLUMNS",
                "RUST_LOG",
                "PYTHONUNBUFFERED",
                "CI",
            ],
            true,
        );
    }

    #[test]
    fn execution_bearing_not_inert() {
        assert_all(
            &[
                "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES",
                "PATH",
                "BASH_ENV",
                "GIT_EXTERNAL_DIFF",
                "GIT_PAGER",
                "PAGER",
                "GIT_EDITOR",
                "TAR_OPTIONS",
                "RIPGREP_CONFIG_PATH",
                "GIT_CONFIG_COUNT",
            ],
            false,
        );
    }

    #[test]
    fn tz_is_not_inert_because_it_can_name_a_file() {
        // `TZ=:/etc/localtime` names a file the process reads, so it fails
        // criterion (b). Zero occurrences in the measured corpus, so excluding
        // it costs nothing.
        assert!(!is_inert("TZ"));
    }

    #[test]
    fn path_naming_lookalikes_not_inert() {
        assert_all(
            &[
                "LOCPATH",
                "NLSPATH",
                "PYTHONPATH",
                "PYTHONSTARTUP",
                "PYTHONHOME",
                "TERMINFO",
                "TERMINFO_DIRS",
                "RUSTFLAGS",
                "RUSTC_WRAPPER",
            ],
            false,
        );
    }

    #[test]
    fn unknown_variable_not_inert() {
        assert_all(&["SKULD_LABELS", "FOO", ""], false);
    }

    #[test]
    fn lc_prefix_is_matched_but_python_prefix_is_not() {
        assert!(is_inert("LC_ANYTHING_NEW"));
        assert!(!is_inert("PYTHON_ANYTHING_NEW"));
    }

    #[test]
    fn comparison_is_case_sensitive() {
        assert_all(&["lc_all", "lang", "no_color"], false);
    }
}
