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
pub fn accesses(redirects: &[Redirect], source: &str, cwd: &str) -> Vec<FileAccess> {
    redirects
        .iter()
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
pub fn accesses_for_redirect(redirect: &Redirect, source: &str, cwd: &str) -> Vec<FileAccess> {
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
            if edge_is_bare_dash(w, source, Edge::First) {
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
fn names_a_descriptor(word: &Word, source: &str) -> bool {
    let Some(s) = word.try_to_static_string() else {
        return false;
    };
    // `>&""` is a "Bad file descriptor" error. It opens nothing.
    if s.is_empty() {
        return true;
    }
    // Closing and duplicating survive quoting: `>&"-"` closes and `>&"2"`
    // duplicates, exactly as their bare spellings do.
    if s == "-" || s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    // An unquoted trailing dash makes bash read the whole word as a descriptor
    // spec whatever precedes it — `>&2-` moves fd 2, `>&x-` is an "ambiguous
    // redirect" — and neither opens a file. Quote that one character and it is
    // an ordinary filename again: `>&"2"-` moves, but `>&2"-"` writes `2-`.
    edge_is_bare_dash(word, source, Edge::Last)
}

/// Which end of a redirect word to inspect.
#[derive(Clone, Copy)]
enum Edge {
    First,
    Last,
}

/// Is the character at `edge` of this word a `-` that bash saw bare?
///
/// Both dash rules turn on how one character was *written*, and the parsed word
/// no longer holds that: `-`, `\-` and `"-"` all arrive as `Literal("-")`. The
/// source byte at the word's edge does hold it, and it decides both rules
/// outright — a `-` there is a bare dash, and a `\` or a quote there means the
/// word's edge character is something bash had to unescape to reach.
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
fn edge_is_bare_dash(word: &Word, source: &str, edge: Edge) -> bool {
    debug_assert!(
        word.span.end.0 <= source.len(),
        "word span {}..{} is outside the source it was parsed from (length {})",
        word.span.start.0,
        word.span.end.0,
        source.len(),
    );
    if word.span.end.0 <= word.span.start.0 {
        return false;
    }
    let index = match edge {
        Edge::First => word.span.start.0,
        Edge::Last => word.span.end.0 - 1,
    };
    source.as_bytes().get(index) == Some(&b'-')
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
fn closed_descriptor_operand(redirect: &Redirect, source: &str) -> Option<(usize, Option<String>)> {
    let word = match &redirect.kind {
        RedirectKind::DupInput(w) | RedirectKind::DupOutput(w) => w,
        _ => return None,
    };
    // Only a bare leading dash terminates the token. Quoting or escaping that
    // one character makes the whole word a filename instead — `>&"-2"` and
    // `>&\-2` both write `-2` — while quoting anywhere *after* it changes
    // nothing: `>&-"vault/creds"` still passes `vault/creds` as an argument.
    if !edge_is_bare_dash(word, source, Edge::First) {
        return None;
    }
    // The `-` is one source byte, so the operand starts one byte into the word.
    let start = word.span.start.0 + 1;
    if start >= word.span.end.0 {
        // A bare `>&-` closes the descriptor and names nothing.
        return None;
    }
    // A static word's value starts with the same `-` its source does, so what
    // follows the dash is the operand. `>&-""` passes an empty argument, which
    // is an argument.
    let text = word
        .try_to_static_string()
        .map(|t| t.strip_prefix('-').unwrap_or(&t).to_string());
    Some((start, text))
}

/// The arguments bash passes to the command, in source order.
///
/// Ordering matters because position is what gives an operand its meaning:
/// `cp a b` reads `a` and writes `b`, so appending a recovered operand instead
/// of splicing it would invert a read and a write. The splice exists only to
/// work around thaum#14; see `closed_descriptor_operand`. Once that lands, this
/// collapses back to mapping `cmd.arguments`.
pub fn command_arg_literals(cmd: &Command, source: &str) -> Vec<Option<String>> {
    let mut items: Vec<(usize, Option<String>)> = cmd
        .arguments
        .iter()
        .map(|a| (a.span().start.0, a.try_to_static_string()))
        .collect();
    items.extend(
        cmd.redirects
            .iter()
            .filter_map(|r| closed_descriptor_operand(r, source)),
    );
    items.sort_by_key(|(pos, _)| *pos);
    items.into_iter().map(|(_, literal)| literal).collect()
}
