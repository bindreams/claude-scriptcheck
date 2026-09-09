use crate::file_access::AccessScope;

use super::{resolve, resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

// ─── find ────────────────────────────────────────────────────────────────────

/// `find` uses a predicate-based syntax that doesn't fit standard option parsing.
/// Leading arguments before the first expression token are search paths (Read).
pub(super) struct FindParser;

impl CommandParser for FindParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let mut i = 0;
        let mut follows_symlinks = false;

        // Global options precede the search paths. `-L` makes the walk follow
        // symlinks, so it can leave the named subtree.
        while i < args.len() {
            match args[i] {
                "-L" => {
                    follows_symlinks = true;
                    i += 1;
                }
                "-H" | "-P" => i += 1,
                // `-D <debugopts>` takes a value, which may be absent if the
                // user typed a trailing `-D`.
                "-D" => i = (i + 2).min(args.len()),
                a if a.starts_with("-O") && a.len() > 2 => i += 1,
                _ => break,
            }
        }

        let mut paths: Vec<&str> = Vec::new();
        let mut rest = &args[i..];
        while let Some(arg) = rest.first() {
            if is_find_expression_token(arg) {
                break;
            }
            paths.push(arg);
            rest = &rest[1..];
        }

        // `-follow` is the expression-position spelling of `-L`, so it only
        // appears after the starting points.
        if rest.contains(&"-follow") {
            follows_symlinks = true;
        }
        let recursion = if follows_symlinks {
            Recursion::Following
        } else {
            Recursion::Yes
        };

        let mut reads: Vec<AccessScope> = paths
            .iter()
            .map(|p| resolve_scoped(p, cwd, recursion))
            .collect();
        if reads.is_empty() {
            // No path operand: find walks the working directory.
            reads.push(resolve_scoped(cwd, cwd, recursion));
        }

        // `-delete` turns the walk into a write over the same set of paths; the
        // printing predicates write one named file each.
        let mut writes = if rest.contains(&"-delete") {
            reads.clone()
        } else {
            Vec::new()
        };
        writes.extend(written_files(rest, cwd));

        // `-files0-from FILE` takes the starting points from FILE (or stdin for
        // `-`), so nothing in the argument list describes what the walk
        // touches. The list itself is a read; the walk needs a `Bash(...)` rule,
        // because a `-delete` driven by it would otherwise reach unchecked
        // paths.
        let list_file = files0_from(rest);
        if let Some(path) = list_file {
            if path != "-" {
                reads.push(resolve(path, cwd));
            }
        }

        // A walk that runs a program, or whose starting points are not visible,
        // is not file-only however tame the paths it names look.
        let file_only = if runs_a_program(rest) || list_file.is_some() {
            Some(false)
        } else {
            None
        };

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only,
            ..Default::default()
        })
    }
}

/// Targets of the predicates that write a file. `-fprint FILE`, `-fprint0 FILE`,
/// `-fls FILE` and `-fprintf FILE FORMAT` each create or truncate `FILE`
/// (verified against GNU find 4.x). The operand is the token right after the
/// predicate; a trailing predicate with no operand records nothing, matching
/// find, which errors out.
///
/// Like `runs_a_program` this does not model predicate arity, so a value that
/// spells `-fprint` yields one spurious `Write` demand — over-approximating on
/// purpose.
fn written_files(expression: &[&str], cwd: &str) -> Vec<AccessScope> {
    let mut writes = Vec::new();
    let mut i = 0;
    while i < expression.len() {
        if matches!(expression[i], "-fprint" | "-fprint0" | "-fls" | "-fprintf") {
            if let Some(target) = expression.get(i + 1) {
                writes.push(resolve(target, cwd));
            }
            // Skip the operand so a target spelled `-fprint` is not re-read as
            // a predicate.
            i += 2;
        } else {
            i += 1;
        }
    }
    writes
}

/// The operand of `-files0-from`, if present. GNU find reads NUL-separated
/// starting points from that file, so the walk's roots are not in the argument
/// list at all.
fn files0_from<'a>(expression: &[&'a str]) -> Option<&'a str> {
    let index = expression.iter().position(|arg| *arg == "-files0-from")?;
    // A trailing `-files0-from` with no operand still hides the roots.
    Some(expression.get(index + 1).copied().unwrap_or("-"))
}

/// Does this expression run an arbitrary program? `-exec`/`-execdir` run one per
/// match, `-ok`/`-okdir` do the same after a prompt `find` itself issues — none
/// of which a `Read`/`Write` rule can gate. The invocation needs the `Bash(...)`
/// rule that gates execution.
///
/// The scan is a flat token search: it does not model predicate arity, so a
/// value that happens to spell `-exec` (`find . -name -exec`) forces the rule
/// too. That is the over-approximating direction — a spurious prompt, never a
/// missed one.
fn runs_a_program(expression: &[&str]) -> bool {
    expression
        .iter()
        .any(|arg| matches!(*arg, "-exec" | "-execdir" | "-ok" | "-okdir"))
}

fn is_find_expression_token(arg: &str) -> bool {
    matches!(
        arg,
        // Tests / predicates
        "-name"
        | "-iname"
        | "-type"
        | "-path"
        | "-ipath"
        | "-regex"
        | "-iregex"
        | "-size"
        | "-perm"
        | "-user"
        | "-group"
        | "-newer"
        | "-mtime"
        | "-atime"
        | "-ctime"
        | "-mmin"
        | "-amin"
        | "-cmin"
        | "-maxdepth"
        | "-mindepth"
        | "-depth"
        | "-empty"
        | "-samefile"
        | "-true"
        | "-false"
        | "-links"
        | "-inum"
        | "-xtype"
        | "-readable"
        | "-writable"
        | "-executable"
        | "-wholename"
        | "-iwholename"
        | "-lname"
        | "-ilname"
        | "-uid"
        | "-gid"
        | "-nouser"
        | "-nogroup"
        | "-xdev"
        | "-mount"
        | "-noleaf"
        | "-daystart"
        | "-follow"
        | "-files0-from"
        | "-warn"
        | "-nowarn"
        | "-regextype"
        | "-used"
        // Actions
        | "-exec"
        | "-execdir"
        | "-ok"
        | "-okdir"
        | "-print"
        | "-print0"
        | "-printf"
        | "-fprintf"
        | "-prune"
        | "-delete"
        | "-quit"
        | "-ls"
        | "-fls"
        | "-fprint"
        | "-fprint0"
        // Operators
        | "-not"
        | "-and"
        | "-or"
        | "-a"
        | "-o"
        | "!"
        | "("
        | ")"
        | ","
    ) || arg.starts_with("-newer") // covers -newerXY variants
}
