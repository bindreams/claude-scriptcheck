use crate::file_access::AccessKind;

/// Builtins we track for shadowing detection.
/// If user code reassigns any of these, we stop treating them as builtins.
const TRACKED_BUILTINS: &[&str] = &["open", "exec", "eval", "compile", "__import__"];

/// Unsafe builtins: calling these (unshadowed) makes the script unanalyzable.
const UNSAFE_BUILTINS: &[&str] = &["exec", "eval", "compile", "__import__"];

/// Unsafe qualified function calls (module.function patterns).
/// These have side effects that cannot be expressed as file accesses.
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
    // Low-level file descriptor open (uses flag constants, not mode strings)
    "os.open",
    // Network I/O
    "urllib.request.urlopen",
];

/// `os.*` functions that take a single path argument and write to it.
/// First positional (or keyword `path`/`name`) → Write.
const OS_WRITE_SINGLE_PATH: &[&str] = &[
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.makedirs",
    "os.mkdir",
    "os.truncate",
    "os.chmod",
    "os.chown",
    "os.chflags",
    "os.lchflags",
    "os.lchmod",
    "os.lchown",
];

/// `os.*` functions that take two path arguments (source, destination).
/// First positional (or keyword `src`) → Read, second (or keyword `dst`) → Write.
/// Note: `os.symlink(src, dst)` doesn't actually read `src` (it stores the string
/// as the link target), but we emit Read(src) as a conservative over-approximation.
const OS_WRITE_SRC_DST: &[&str] = &[
    "os.rename",
    "os.renames",
    "os.replace",
    "os.link",
    "os.symlink",
];

/// Classification of `os.*` file-mutation calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsCallKind {
    /// Single path → Write (e.g. `os.remove(path)`)
    WriteSinglePath,
    /// Two paths → Read(src) + Write(dst) (e.g. `os.rename(src, dst)`)
    WriteSrcDst,
}

pub fn is_tracked_builtin(name: &str) -> bool {
    TRACKED_BUILTINS.contains(&name)
}

pub fn is_unsafe_builtin(name: &str) -> bool {
    UNSAFE_BUILTINS.contains(&name)
}

pub fn is_unsafe_qualified(qualified: &str) -> bool {
    UNSAFE_QUALIFIED.contains(&qualified)
}

/// Classify an `os.*` file-mutation call, if recognized.
pub fn classify_os_call(qualified: &str) -> Option<OsCallKind> {
    if OS_WRITE_SINGLE_PATH.contains(&qualified) {
        Some(OsCallKind::WriteSinglePath)
    } else if OS_WRITE_SRC_DST.contains(&qualified) {
        Some(OsCallKind::WriteSrcDst)
    } else {
        None
    }
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
