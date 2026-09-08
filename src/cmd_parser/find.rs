use crate::file_access::AccessScope;

use super::{resolve_scoped, CommandFileAccesses, CommandParser, Recursion};

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

        // `-delete` / `-fprint`-style actions turn the walk into a write over
        // the same set of paths.
        let writes = if rest.contains(&"-delete") {
            reads.clone()
        } else {
            Vec::new()
        };

        Ok(CommandFileAccesses {
            reads,
            writes,
            inline_script_start: None,
            file_only: None,
            ..Default::default()
        })
    }
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
