use super::{resolve, CommandFileAccesses, CommandParser};

// ─── find ────────────────────────────────────────────────────────────────────

/// `find` uses a predicate-based syntax that doesn't fit standard option parsing.
/// Leading arguments before the first expression token are search paths (Read).
pub(super) struct FindParser;

impl CommandParser for FindParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let mut reads = Vec::new();

        for arg in args {
            if is_find_expression_token(arg) {
                break;
            }
            reads.push(resolve(arg, cwd));
        }

        Ok(CommandFileAccesses {
            reads,
            writes: Vec::new(),
            inline_script_start: None,
            file_only: None,
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
        | "-warn"
        | "-nowarn"
        | "-follow"
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
