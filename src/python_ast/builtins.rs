use crate::file_access::AccessKind;

/// Builtins we track for shadowing detection.
/// If user code reassigns any of these, we stop treating them as builtins.
const TRACKED_BUILTINS: &[&str] = &["open", "exec", "eval", "compile", "__import__"];

/// Unsafe builtins: calling these (unshadowed) makes the script unanalyzable.
const UNSAFE_BUILTINS: &[&str] = &["exec", "eval", "compile", "__import__"];

/// Unsafe qualified function calls (module.function patterns).
/// Includes both process-execution functions and file-mutating functions
/// that we cannot yet extract proper file accesses from.
const UNSAFE_QUALIFIED: &[&str] = &[
    // Process execution
    "os.system",
    "os.popen",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    // File-mutating operations (not yet analyzed for file accesses)
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.rename",
    "os.renames",
    "os.replace",
    "os.link",
    "os.symlink",
    "os.makedirs",
    "os.mkdir",
    "os.truncate",
    "os.chmod",
    "os.chown",
    "os.chflags",
    "os.lchflags",
    "os.lchmod",
    "os.lchown",
    // Low-level file descriptor open (uses flag constants, not mode strings)
    "os.open",
];

pub fn is_tracked_builtin(name: &str) -> bool {
    TRACKED_BUILTINS.contains(&name)
}

pub fn is_unsafe_builtin(name: &str) -> bool {
    UNSAFE_BUILTINS.contains(&name)
}

pub fn is_unsafe_qualified(qualified: &str) -> bool {
    UNSAFE_QUALIFIED.contains(&qualified)
}

/// Classify an `open()` mode string into Read or Write access.
///
/// Python mode characters:
/// - `r` = read (default)
/// - `w` = write (truncate)
/// - `a` = append
/// - `x` = exclusive create
/// - `+` = read+write (upgrade to write)
/// - `b` / `t` = binary / text (modifiers, don't affect access kind)
pub fn classify_open_mode(mode: &str) -> AccessKind {
    if mode.contains('w') || mode.contains('a') || mode.contains('x') || mode.contains('+') {
        AccessKind::Write
    } else {
        AccessKind::Read
    }
}
