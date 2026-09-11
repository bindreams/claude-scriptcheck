//! What a redirect does to the filesystem.
//!
//! A redirect names a file, duplicates a descriptor, or carries inline text,
//! and the answer comes from bash's tokenisation rather than from a table of
//! spellings: tokenisation decides where the redirect target ends, and
//! interpretation decides what the surviving word means. Getting it wrong is
//! expensive in both directions — a file read as a descriptor slips past every
//! rule, and a descriptor read as a file produces a deny no rule can lift.

use thaum::ast::*;

use crate::file_access::{self, AccessKind, FileAccess};

/// The file accesses a command's redirects perform.
///
/// `source` is the text the command was parsed from, or `None` where that text
/// is not available — see `edge_is_bare_dash`. Redirects at or after
/// `comment_at` are skipped: a comment runs to the end of the line, so bash
/// never performs them.
pub fn accesses(
    redirects: &[Redirect],
    source: Option<&str>,
    cwd: &str,
    comment_at: Option<usize>,
) -> Vec<FileAccess> {
    redirects
        .iter()
        .filter(|r| comment_at.is_none_or(|at| r.span.start.0 < at))
        .flat_map(|r| accesses_for_redirect(r, source, cwd))
        .collect()
}

/// The file accesses one redirect performs.
///
/// Empty means the redirect opens no file, and every such arm says why rather
/// than defaulting — see the match arms below.
///
/// A redirect can name a file in more than one way, hence the `Vec`: `<>` opens
/// one path for both reading and writing.
pub fn accesses_for_redirect(
    redirect: &Redirect,
    source: Option<&str>,
    cwd: &str,
) -> Vec<FileAccess> {
    use AccessKind::{Read, Write};

    let (word, kinds): (&Word, &[AccessKind]) = match &redirect.kind {
        RedirectKind::Input(w) => (w, &[Read]),
        RedirectKind::Output(w) | RedirectKind::Clobber(w) | RedirectKind::Append(w) => {
            (w, &[Write])
        }
        RedirectKind::BashOutputAll(w) | RedirectKind::BashAppendAll(w) => (w, &[Write]),
        // `<>file` opens the file for reading *and* writing (Bash §3.6.10), so
        // a `Read` deny rule has to fire on it as well as a `Write` one.
        RedirectKind::ReadWrite(w) => (w, &[Read, Write]),
        // The body is inline text — no file is named.
        RedirectKind::HereDoc { .. } | RedirectKind::BashHereString(_) => return Vec::new(),
        // `<&word` takes only descriptor forms. Any other word is a redirection
        // error, not a file open: the file special case below is output-only.
        // Verified: `log hi <&foo` fails with "ambiguous redirect".
        RedirectKind::DupInput(_) => return Vec::new(),
        RedirectKind::DupOutput(w) => {
            // Bash §3.6.8 says "if n is omitted", but bash also redirects when
            // n is 1 — `1>&f`, and zero-padded spellings like `001>&f`, all
            // create `f`. thaum parses the descriptor as a number, so the
            // padding collapses on its own. Every other descriptor is an
            // "ambiguous redirect" error that opens nothing, verified for
            // `0>&f`, `2>&f`, `3>&f` and `10>&f`.
            let redirects_stdout = matches!(redirect.fd, None | Some(1));
            if !redirects_stdout || names_a_descriptor(w, source) {
                return Vec::new();
            }
            // A bare leading dash closes the descriptor and ends the token;
            // what follows is a separate word, recovered by
            // `closed_descriptor_operand`. Nothing here opens a file.
            //
            // An unknown source cannot answer this, and the two readings need
            // opposite answers, so both are taken: the write is recorded here
            // and the operand is recovered anyway. One of them is spurious and
            // neither is missing.
            if edge_is_bare_dash(w, source, Edge::First) == Some(true) {
                return Vec::new();
            }
            (w, &[Write])
        }
    };

    // A target that does not resolve statically is dropped, exactly as before.
    // Recording it instead is #45's job, and deliberately not this change's.
    let Some(path) = word.try_to_static_string() else {
        return Vec::new();
    };
    // An empty target is a redirection error in every form — `> ""` and `<> ""`
    // report "No such file or directory", `>& ""` reports "Bad file
    // descriptor" — and bash abandons the command without opening anything.
    // Resolving it instead names the working directory, which is not a file the
    // command touches and which a `Deny(Write(...))` would then fire on.
    if path.is_empty() {
        return Vec::new();
    }
    let resolved = file_access::resolve_path(&path, cwd);
    kinds
        .iter()
        .map(|kind| FileAccess::exact(resolved.clone(), *kind))
        .collect()
}

/// Does this `>&word` / `<&word` target name a descriptor instead of a file?
///
/// Three forms do, and none of them is a filename:
///
/// - `digits` — duplicate that descriptor (Bash §3.6.8), `>&2`
/// - `-` — close the descriptor (§3.6.8), `>&-`
/// - `digits-` — *move* the descriptor: duplicate, then close the source
///   (§3.6.9), `>&2-`
///
/// The move form is worth spelling out: reading its trailing `-` as part of a
/// filename turns `>&2-` into a write to a file called `2-`, which a
/// `Deny(Write(...))` over the directory then blocks — a false deny on a valid
/// command, and no rule the user adds can lift it.
///
/// A leading `-` is *not* this: `>&-2` opens a file called `-2`, because the
/// word is neither digits nor `-`.
///
/// A word that does not resolve statically could be any of these or a filename.
/// Of those readings only the file one needs checking, so it is not treated as
/// a descriptor.
fn names_a_descriptor(word: &Word, source: Option<&str>) -> bool {
    let Some(s) = word.try_to_static_string() else {
        return false;
    };
    // Closing and duplicating survive quoting: `>&"-"` closes and `>&"2"`
    // duplicates, exactly as their bare spellings do. The empty word takes the
    // digits branch too, `all` being vacuously true over no bytes — which is
    // the right answer rather than an accident to guard against, since `>&""`
    // is a "Bad file descriptor" error and opens nothing either.
    if s == "-" || s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    // An unquoted trailing dash makes bash read the whole word as a descriptor
    // spec whatever precedes it — `>&2-` moves fd 2, `>&x-` is an "ambiguous
    // redirect" — and neither opens a file. Quote that one character and it is
    // an ordinary filename again: `>&"2"-` moves, but `>&2"-"` writes `2-`.
    // With no source the character's spelling is unknown. Reading it as a
    // descriptor would drop a file access, so it is read as a filename: the
    // over-approximating direction.
    edge_is_bare_dash(word, source, Edge::Last) == Some(true)
}

/// Which end of a redirect word to inspect.
#[derive(Clone, Copy)]
enum Edge {
    First,
    Last,
}

/// Is the character at `edge` of this word a `-` that bash saw bare?
///
/// `None` when the source the word was parsed from is not available, which is
/// not the same as "no". Both dash rules turn on how one character was
/// *written*, and the parsed word no longer holds that: `-`, `\-` and `"-"` all
/// arrive as `Literal("-")`. The source byte at the word's edge does hold it,
/// and it decides both rules outright — a `-` there is a bare dash, and a `\`
/// or a quote there means the word's edge character is something bash had to
/// unescape to reach.
///
/// This is also what makes the two edges behave differently, which is the part
/// of bash's grammar nobody predicts:
///
/// ```text
/// >&\-2   >&"-2"    both write a file called `-2`
/// >&2\-             moves fd 2, exactly as `>&2-` does
/// >&2"-"            writes a file called `2-`
/// ```
///
/// One rule reads one byte and reproduces all four, because the byte at the
/// leading edge of `\-2` is `\` while the byte at the trailing edge of `2\-`
/// is `-`.
///
/// # When the source is unknown
///
/// Spans are positions in the text the node was parsed from, and thaum parses a
/// command substitution's body separately: spans inside `$(...)`, `` `...` ``
/// and `<(...)` restart at zero. Indexing the outer command's text with them
/// reads another command's bytes — which is a wrong answer, not a missing one,
/// so the caller re-bases the source when it descends and passes `None` where
/// it cannot. Tracked as thaum#50.
fn edge_is_bare_dash(word: &Word, source: Option<&str>, edge: Edge) -> Option<bool> {
    let source = source?;
    debug_assert!(
        word.span.end.0 <= source.len(),
        "word span {}..{} is outside the source it was parsed from (length {})",
        word.span.start.0,
        word.span.end.0,
        source.len(),
    );
    // A word with no source bytes has no edge character. No parse produces one,
    // but the subtraction below would underflow if one ever did.
    if word.span.end.0 <= word.span.start.0 {
        return Some(false);
    }
    let index = match edge {
        Edge::First => word.span.start.0,
        Edge::Last => word.span.end.0 - 1,
    };
    Some(source.as_bytes().get(index) == Some(&b'-'))
}

/// The argument hiding inside a `>&-word` / `<&-word` redirect: where it starts
/// in the source, and its text when that resolves statically.
///
/// thaum lexes the whole of `-word` as one redirect target. bash does not: it
/// reads `>&-` as "close the descriptor" and then `word` as a plain argument.
/// Verified — `log hi >&-2` reports `argc=2 [hi 2]` and creates no file.
///
/// The difference hides an operand. `cp >&-vault/creds stolen.txt` copies
/// `vault/creds`, but thaum's argument list holds only `stolen.txt`, so without
/// this the read never reaches the rules and a `Deny(Read(vault/**))` cannot
/// fire on it.
///
/// A `None` text means the operand is real but its value is not static, as in
/// `>&-$P` or `>&-pat*`. It still occupies a position, so it is spliced in as
/// the same unresolved marker any other dynamic argument gets: dropping it
/// would shift every later positional, and shifting one turns a source into a
/// destination.
///
/// # This is a workaround, and it has somewhere to go
///
/// The divergence is a lexer bug, tracked as thaum#14
/// (<https://github.com/bindreams/thaum/issues/14>). Reconstructing bash's
/// argument list here means scriptcheck reimplements a lexing rule on top of a
/// parse that got it wrong — worth it while a live read bypass is open, but not
/// where the fix belongs. When thaum#14 lands the operand arrives as an ordinary
/// `Argument`, and this function and its call in `command_arg_literals` should
/// be deleted rather than adapted.
fn closed_descriptor_operand<'a>(
    redirect: &Redirect,
    source: Option<&'a str>,
) -> Option<RecoveredOperand<'a>> {
    let word = match &redirect.kind {
        RedirectKind::DupInput(w) | RedirectKind::DupOutput(w) => w,
        _ => return None,
    };
    // Only a bare leading dash terminates the token. Quoting or escaping that
    // one character makes the whole word a filename instead — `>&"-2"` and
    // `>&\-2` both write `-2` — while quoting anywhere *after* it changes
    // nothing: `>&-"vault/creds"` still passes `vault/creds` as an argument.
    //
    // With no source to read, a value starting with `-` is recovered anyway:
    // the write was recorded as well, so one reading is spurious and the
    // operand — which can hide a denied path — is not missed.
    let value = word.try_to_static_string();
    match edge_is_bare_dash(word, source, Edge::First) {
        Some(true) => {}
        Some(false) => return None,
        None if value.as_deref().is_some_and(|v| v.starts_with('-')) => {}
        None => return None,
    }
    // The `-` is one source byte, so the operand starts one byte into the word.
    let position = word.span.start.0 + 1;
    if position >= word.span.end.0 {
        // A bare `>&-` closes the descriptor and names nothing.
        return None;
    }
    // A static word's value starts with the same `-` its source does, so what
    // follows the dash is the operand. `>&-""` passes an empty argument, which
    // is an argument.
    let literal = value.map(|t| t.strip_prefix('-').unwrap_or(&t).to_string());
    Some(RecoveredOperand {
        position,
        // Which kind of word bash reads this as is decided from the spelling,
        // so without the source it cannot be decided: an argument is the
        // reading that keeps its position and its access.
        text: source.and_then(|s| s.get(position..word.span.end.0)),
        literal,
    })
}

/// An argument bash took out of a `>&-word` redirect.
struct RecoveredOperand<'a> {
    /// Where the operand starts in the source, which is its position among the
    /// command's words.
    position: usize,
    /// The operand as written, when the source it came from is known. What
    /// kind of word bash reads it as — an argument, an assignment, the start of
    /// a comment — is decided from the spelling, before any expansion.
    text: Option<&'a str>,
    /// Its value, when the word resolves statically.
    literal: Option<String>,
}

impl RecoveredOperand<'_> {
    /// Does this operand start a comment, ending the command line?
    ///
    /// `>&-` ends the redirect token, so what follows begins a fresh word — and
    /// a word starting with `#` is a comment. Verified: `p in >&-#foo bar`
    /// reports `argc=1 [in]`, so both `#foo` and `bar` are comment text.
    fn starts_a_comment(&self) -> bool {
        self.text.is_some_and(|t| t.starts_with('#'))
    }

    /// Would bash read this operand as a variable assignment?
    ///
    /// Only in the command prefix, which the caller decides. A word is an
    /// assignment when it starts with a name followed by `=` or `+=` — a rule
    /// about the spelling, not the value, so `>&-$P` is a command word even if
    /// `$P` expands to `FOO=1`. Verified: `>&-FOO=1 p x` reports `argc=1 [x]`
    /// with `FOO=1` in the environment, while `>&-1FOO=1 p x` is a
    /// `command not found` for `1FOO=1` — an invalid name is an ordinary word.
    fn is_assignment(&self) -> bool {
        self.text.is_some_and(is_assignment_word)
    }
}

/// Would bash read this word as a variable assignment?
///
/// Only in the command prefix, which the caller decides. A word is an
/// assignment when it starts with a name — optionally with an array subscript —
/// followed by `=` or `+=`. The rule is about the spelling, not the value, so
/// `$P` is a command word even if it expands to `FOO=1`. Verified:
/// `>&-FOO=1 p x` and `>&-a[0]=1 p x` both run `p` with `x`, while
/// `>&-1FOO=1 p x` is a `command not found` for `1FOO=1` — an invalid name is
/// an ordinary word.
fn is_assignment_word(text: &str) -> bool {
    let Some((before, _)) = text.split_once('=') else {
        return false;
    };
    let name = before.strip_suffix('+').unwrap_or(before);
    // An array element assignment names an index: `a[0]=1`, `a[$i]=1`.
    let name = match name.split_once('[') {
        Some((name, subscript)) if subscript.ends_with(']') => name,
        Some(_) => return false,
        None => name,
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// What the command line says: the arguments bash passes, and where a comment
/// begins if one does.
pub struct CommandLine {
    /// Argument literals in source order, arg0 first, with `None` for a word
    /// that does not resolve statically.
    pub arguments: Vec<Option<String>>,
    /// Where a comment starts, if a recovered operand began one. A comment runs
    /// to the end of the line, so the redirects after it are never performed.
    pub comment_at: Option<usize>,
}

/// Read a command's words the way bash does, in source order.
///
/// Ordering matters because position is what gives a word its meaning: `cp a b`
/// reads `a` and writes `b`, and the words before the command name are
/// assignments while the ones after it are arguments. The parser sorted the
/// words *it* saw, but `>&-word` hides one from it — so where that hidden word
/// lands changes what every later word means, and the sorting has to be redone
/// over all of them together.
///
/// The splice exists only to work around thaum#14; see
/// `closed_descriptor_operand`. Once that lands, this collapses back to mapping
/// `cmd.arguments`.
pub fn command_line(cmd: &Command, source: Option<&str>) -> CommandLine {
    enum Word<'a> {
        /// A word the parser saw as an argument. It is one by construction:
        /// the parser only reaches arguments past the command name.
        Argument(Option<String>),
        /// A word the parser saw as an assignment, which it is only while no
        /// command name has appeared. A recovered operand can supply that name
        /// earlier, and then this is an ordinary argument — `>&-env FOO=1 rm x`
        /// runs `env` with `FOO=1` as its first argument.
        Assignment(Option<String>),
        /// A word recovered from a `>&-word` redirect, which the parser did not
        /// see at all, so bash's rules for what kind of word it is have to be
        /// applied here.
        Recovered(RecoveredOperand<'a>),
    }

    impl Word<'_> {
        /// Is this word part of the command prefix rather than the command?
        fn is_prefix_assignment(&self) -> bool {
            match self {
                Word::Argument(_) => false,
                Word::Assignment(_) => true,
                Word::Recovered(operand) => operand.is_assignment(),
            }
        }

        fn literal(&self) -> Option<String> {
            match self {
                Word::Argument(literal) | Word::Assignment(literal) => literal.clone(),
                Word::Recovered(operand) => operand.literal.clone(),
            }
        }
    }

    let mut words: Vec<(usize, Word)> = cmd
        .arguments
        .iter()
        .map(|a| (a.span().start.0, Word::Argument(a.try_to_static_string())))
        .collect();
    words.extend(cmd.assignments.iter().map(|a| {
        // As an argument it is one word, `name=value`, however its value was
        // quoted. An array literal — `name=(a b)` — is not reconstructed.
        let literal = match &a.value {
            AssignmentValue::Scalar(word) => word
                .try_to_static_string()
                .map(|value| format!("{}={}", a.name, value)),
            _ => None,
        };
        (a.span.start.0, Word::Assignment(literal))
    }));
    words.extend(
        cmd.redirects
            .iter()
            .filter_map(|r| closed_descriptor_operand(r, source))
            .map(|operand| (operand.position, Word::Recovered(operand))),
    );
    words.sort_by_key(|(position, _)| *position);

    // A recovered operand starting with `#` is a comment, and a comment runs to
    // the end of the line: every word after it is comment text, and so is every
    // redirect.
    let comment_at = words
        .iter()
        .find(|(_, w)| matches!(w, Word::Recovered(o) if o.starts_a_comment()))
        .map(|(position, _)| *position);
    if let Some(at) = comment_at {
        words.retain(|(position, _)| *position < at);
    }

    // The command name is the first word that is not an assignment; everything
    // before it is the prefix, and everything after it is an argument whatever
    // it looks like. Treating `>&-FOO=1 rm -rf zzz` as a command called `FOO=1`
    // would leave every `Bash(rm ...)` rule looking at a name nothing matches.
    let command_name = words.iter().position(|(_, w)| !w.is_prefix_assignment());
    let arguments = match command_name {
        Some(first) => words[first..].iter().map(|(_, w)| w.literal()).collect(),
        // Every word was an assignment: an assignment-only command, which runs
        // nothing but still performs its redirects.
        None => Vec::new(),
    };
    CommandLine {
        arguments,
        comment_at,
    }
}
