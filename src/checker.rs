use std::ops::Range;

use thaum::ast::*;
use thaum::visit::Visit;

use crate::cmd_parser::{self, CmdParseResult};
use crate::env_prefix;
use crate::file_access::{self, AccessKind, AccessScope, FileAccess};
use crate::filter::{Arg0Pattern, BashFilter, BashFilterItem, Filter, PathFilter};
use crate::permission::ParsedPermissions;
use crate::permission_mode::PermissionMode;
use crate::python_ast::{self, PythonAnalysis};
use crate::redirect;

/// Final decision for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask,
}

/// Full result of checking a program, including which rules matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub decision: Decision,
    /// Allow rules that matched (Bash, Read, Write, Edit).
    pub matched_allow: Vec<String>,
    /// Deny rules that matched (at most one in practice).
    pub matched_deny: Vec<String>,
    /// Rules that would need to be allowed for the decision to be Allow.
    /// Populated whenever at least one rule went unmatched, regardless of the final
    /// decision. Surviving the `apply_permission_mode` transform is the point:
    /// after Ask → Allow in bypass/auto, the log can still show what was missing.
    pub missing_rules: Vec<String>,
    /// Optional override for the user-facing reason text in `log_and_output`.
    /// Used by synthetic Ask sites (parse failures, missing file paths) to preserve
    /// their informative reason across the `apply_permission_mode` transform.
    pub custom_reason: Option<String>,
    /// Advisory lines shown after the missing-rule list, never inside it.
    ///
    /// `missing_rules` is a list of rules the user can paste into
    /// `permissions.allow`, and every consumer iterates it on that assumption —
    /// `cli::check` prints them as a bullet list, and `dontAsk` joins them into
    /// "requires rule(s) not in settings: …, add the listed rule(s)". Anything
    /// that is not a pasteable rule must go here instead: an explanation put in
    /// `missing_rules` gets rendered as a rule and instructs the reader to paste
    /// it, which is exactly what happened to the environment-assignment note.
    pub notes: Vec<String>,
}

/// Transform a `CheckResult`'s decision based on the active permission mode.
///
/// Applied at the **end** of the decision pipeline. Only `Decision::Ask` is
/// transformed: in `BypassPermissions` / `Auto` it becomes `Allow`; in `DontAsk`
/// it becomes `Deny`. `Allow` and `Deny` pass through unchanged in every mode —
/// a deny rule is authoritative everywhere, including bypass, matching Claude
/// Code's own documented behavior for hook-deny.
///
/// `missing_rules` on the result is preserved regardless of outcome, so the log
/// can still record what was unmatched even when the final verdict is Allow.
pub fn apply_permission_mode(mut result: CheckResult, mode: Option<PermissionMode>) -> CheckResult {
    use PermissionMode::*;
    let decision = std::mem::replace(&mut result.decision, Decision::Allow);
    result.decision = match (decision, mode) {
        (Decision::Ask, Some(BypassPermissions | Auto)) => Decision::Allow,
        (Decision::Ask, Some(DontAsk)) => {
            let missing = if result.missing_rules.is_empty() {
                // Invariant ordinarily holds via `finalize()`, but guard anyway so
                // release builds emit a coherent reason if a synthetic `CheckResult`
                // is ever constructed with an empty `missing_rules`.
                "<unspecified rule>".to_string()
            } else {
                result.missing_rules.join(", ")
            };
            let base = format!(
                "dontAsk mode: command requires rule(s) not in settings: {missing}. \
                 Add the listed rule(s) to permissions.allow to run this.",
            );
            // Preserve custom_reason context (e.g. "Shell command could not be parsed")
            // by prefixing it — the deny payload becomes the source of truth for the
            // final reason, since Decision::Deny's reason is always shown to the user.
            let reason = match &result.custom_reason {
                Some(ctx) if !ctx.is_empty() => format!("{ctx}. {base}"),
                _ => base,
            };
            // Notes go after the paste instruction, never inside the rule list
            // it refers to.
            let reason = if result.notes.is_empty() {
                reason
            } else {
                format!("{reason} Note: {}.", result.notes.join("; "))
            };
            Decision::Deny(reason)
        }
        (other, _) => other,
    };
    result
}

/// Top-level entry point: check a parsed program against permission rules.
pub fn check_program(
    program: &Program,
    source: &str,
    perms: &ParsedPermissions,
    cwd: &str,
) -> CheckResult {
    let mut checker = PermissionChecker {
        perms,
        cwd,
        comment: None,
        source: Some(source),
        unmatched: Vec::new(),
        notes: Vec::new(),
        denied: None,
        matched_allow: Vec::new(),
        matched_deny: Vec::new(),
    };
    checker.visit_program(program);
    checker.finalize()
}

/// Check file accesses against permission rules, without parsing bash.
/// Used for non-Bash tools (Read, Write, Edit, Grep, Glob).
pub fn check_file_accesses(
    accesses: &[FileAccess],
    perms: &ParsedPermissions,
    cwd: &str,
) -> CheckResult {
    let mut checker = PermissionChecker {
        perms,
        cwd,
        comment: None,
        // No program, so no redirect can need its source.
        source: None,
        unmatched: Vec::new(),
        notes: Vec::new(),
        denied: None,
        matched_allow: Vec::new(),
        matched_deny: Vec::new(),
    };
    for access in accesses {
        checker.check_file_access(access, false);
        if checker.denied.is_some() {
            break;
        }
    }
    checker.finalize()
}

struct PermissionChecker<'a> {
    perms: &'a ParsedPermissions,
    cwd: &'a str,
    /// The half-open range a comment silences in the text currently being
    /// walked, if one does.
    ///
    /// A comment runs to the end of the *line* — not to the end of the command
    /// that revealed it, and not to the end of the program. `cat x >&-#foo |
    /// rm -rf zzz` runs no `rm`, but the command on the next line runs
    /// normally, so the range ends at the newline. Scoped like `source`,
    /// because a comment inside `$(...)` ends that line, not the outer one.
    ///
    /// Needs the source to find the newline, so with no source nothing is
    /// silenced beyond the words of the command that revealed the comment —
    /// the over-approximating direction.
    comment: Option<Range<usize>>,
    /// The text the AST currently being walked was parsed from, or `None`
    /// where it is not available.
    ///
    /// Redirect classification turns on how a character was *written* — `-`,
    /// `\-` and `"-"` all parse to the same literal — so the source has to
    /// travel with the AST. It is not one string for the whole walk: thaum
    /// parses a command substitution's body separately, so spans inside
    /// `$(...)`, `` `...` `` and `<(...)` restart at zero and this is re-based
    /// with them. See `crate::redirect`.
    source: Option<&'a str>,
    unmatched: Vec<String>,
    notes: Vec<String>,
    denied: Option<String>,
    matched_allow: Vec<String>,
    matched_deny: Vec<String>,
}

// ─── Visit trait implementation ──────────────────────────────────────────────
//
// Default traversal handles: program → statement → expression → compound → etc.
// We only override the nodes where domain logic lives.

impl<'ast> Visit<'ast> for PermissionChecker<'_> {
    fn visit_command(&mut self, cmd: &'ast Command) {
        if self.denied.is_some() || self.is_commented_out(cmd.span.start.0) {
            return;
        }
        // `check_command` first: it is what discovers a comment in this
        // command's own words, and the assignments below can sit inside it —
        // `>&-#foo V=$(rm -rf x)` runs nothing at all.
        self.check_command(cmd);
        if self.denied.is_some() {
            return;
        }
        // Assignment values are expanded before the command runs.
        // `walk_assignment` routes both `Scalar` and array values into
        // `visit_word`, which is why nothing here enumerates the two shapes.
        // This also covers assignment-only commands (`X=$(...)`), which
        // `check_command` returns from early.
        for assignment in &cmd.assignments {
            if self.is_commented_out(assignment.span.start.0) {
                continue;
            }
            self.visit_assignment(assignment);
        }
        if self.denied.is_some() {
            return;
        }
        // Walk arguments for embedded process substitutions / command substitutions.
        // Don't call walk_command — we already handled redirects inside check_command,
        // and their words are #65.
        for arg in &cmd.arguments {
            if self.is_commented_out(arg.span().start.0) {
                continue;
            }
            self.visit_argument(arg);
        }
    }

    fn visit_redirect(&mut self, redirect: &'ast Redirect) {
        if self.is_commented_out(redirect.span.start.0) {
            return;
        }
        // Handles redirects for compound / function-def contexts (e.g.
        // `{ ...; } > /log`). Simple-command redirects are handled inside
        // `check_command` via `redirect::accesses`. Compound redirects
        // are not bound to a single command, so no Bash allow rule can
        // suppress them.
        if self.denied.is_some() {
            return;
        }
        for access in redirect::accesses_for_redirect(redirect, self.source, self.cwd) {
            self.check_file_access(&access, false);
            if self.denied.is_some() {
                return;
            }
        }
    }

    fn visit_argument(&mut self, arg: &'ast Argument) {
        if self.denied.is_some() {
            return;
        }
        match arg {
            Argument::Atom(Atom::BashProcessSubstitution { body, .. }) => {
                let span = arg.span();
                let source = self
                    .slice(span.start.0, span.end.0)
                    .and_then(process_substitution_body);
                self.visit_nested(body, source);
            }
            Argument::Word(w) => {
                self.visit_word(w);
            }
        }
    }

    /// The word funnel.
    ///
    /// thaum documents word-level traversal as opt-in: `Visit::visit_word` is
    /// a no-op leaf, and every `Word` in the AST reaches it through the
    /// `walk_*` functions. Overriding it here is what makes a command
    /// substitution get checked wherever it hides — assignment values, `for`
    /// and `select` word lists, `case` scrutinees and arm patterns — instead
    /// of only in the positions this checker happens to hand-walk. Adding a
    /// position is then routing its word here, not writing a new mechanism.
    ///
    /// Redirect words are the exception, and deliberately so: `visit_redirect`
    /// intercepts them before `walk_redirect` can deliver them, and closing
    /// that is issue #65.
    fn visit_word(&mut self, word: &'ast Word) {
        if self.denied.is_some() || self.is_commented_out(word.span.start.0) {
            return;
        }
        // The word's own source, so a substitution inside it can be walked
        // against the text it was parsed from rather than the enclosing
        // command's. See `visit_nested`.
        // Resolved once, for the word as a whole: a substitution's body is
        // locatable only when it is the entire word, so every fragment below
        // shares one answer.
        let body = sole_substitution_body(word, self.slice(word.span.start.0, word.span.end.0));
        for fragment in &word.parts {
            self.check_fragment_command_subs(fragment, body);
        }
    }
}

/// The text a substitution was parsed from, when the word is nothing but that
/// substitution.
///
/// `$(cmd)`, `` `cmd` `` and their quoted form `"$(cmd)"` wrap the body in a
/// fixed prefix and suffix, so the body is the slice between them — and the
/// spans thaum produced inside the body index exactly that slice.
///
/// The word has to be checked structurally, not by looking at its text.
/// `$(a)$(b)` also starts with `$(` and ends with `)`, and stripping those
/// yields `a)$(b` — a source that is wrong rather than absent, which is the one
/// outcome worse than not knowing. So the body is returned only for a word
/// whose entire content is the one substitution; `pre$(cmd)post` and
/// `$(a)$(b)` get `None`, and `None` makes the classifier over-approximate.
///
/// Locating a substitution inside a word that holds anything else means
/// re-deriving where each fragment started, which the parse dropped. That is
/// the second half of thaum#50.
fn sole_substitution_body<'a>(word: &Word, word_source: Option<&'a str>) -> Option<&'a str> {
    // `"$(cmd)"`: one quoted fragment wrapping one substitution.
    let parts = match word.parts.as_slice() {
        [Fragment::DoubleQuoted(inner)] => inner.as_slice(),
        other => other,
    };
    if !matches!(parts, [Fragment::CommandSubstitution(_)]) {
        return None;
    }
    // An assignment's value word spans the whole `name=value`, so the name
    // comes off first — before the quotes, since `v="$(cmd)"` wears both.
    let source = strip_assignment_name(word_source?);
    let unquoted = source
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(source);
    // `$(cmd)` only. A backtick substitution's body is *not* the bytes between
    // the backticks: bash resolves `\$`, `` \` `` and `\\` inside it before
    // parsing, so the text that was parsed is shorter than the slice and every
    // span inside it is shifted. Slicing anyway reads the wrong bytes, which is
    // how `` `cat \$\$\$\$- >&vault/creds` `` came out as a read of
    // `vault/creds` when bash writes it. Unknown is the honest answer.
    unquoted
        .strip_prefix("$(")
        .and_then(|body| body.strip_suffix(')'))
}

/// `name=` / `name+=` removed from the front, if one is there.
fn strip_assignment_name(text: &str) -> &str {
    let Some((before, after)) = text.split_once('=') else {
        return text;
    };
    let name = before.strip_suffix('+').unwrap_or(before);
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        after
    } else {
        text
    }
}

/// The text a process substitution was parsed from.
///
/// `<(cmd)` and `>(cmd)` are a whole argument rather than a fragment of a word,
/// so there is no question of what else the word holds.
fn process_substitution_body(source: &str) -> Option<&str> {
    source
        .strip_prefix("<(")
        .or_else(|| source.strip_prefix(">("))
        .and_then(|body| body.strip_suffix(')'))
}

// ─── Domain logic ────────────────────────────────────────────────────────────

impl<'a> PermissionChecker<'a> {
    fn finalize(mut self) -> CheckResult {
        self.unmatched.sort();
        self.unmatched.dedup();
        self.notes.sort();
        self.notes.dedup();
        // A native deny is authoritative and names its own reason, so rules
        // collected for *other* commands in the program are not "rules that
        // would need to be allowed" for anything — the deny stands whatever the
        // user adds. `main.rs` documents native denies as carrying an empty
        // list and the log writer relies on it; without this, a program like
        // `unknown_cmd; rm -rf x` denied on `rm` still reported
        // `Bash(unknown_cmd)` as missing, polluting the audit log with an entry
        // about a different command.
        if self.denied.is_some() {
            self.unmatched.clear();
            self.notes.clear();
        }
        let decision = if let Some(reason) = self.denied {
            Decision::Deny(reason)
        } else if self.unmatched.is_empty() {
            Decision::Allow
        } else {
            Decision::Ask
        };

        self.matched_allow.sort();
        self.matched_allow.dedup();
        self.matched_deny.sort();
        self.matched_deny.dedup();

        CheckResult {
            decision,
            missing_rules: self.unmatched,
            custom_reason: None,
            notes: self.notes,
            matched_allow: self.matched_allow,
            matched_deny: self.matched_deny,
        }
    }

    fn deny(&mut self, reason: String) {
        if self.denied.is_none() {
            self.denied = Some(reason);
        }
    }

    fn check_command(&mut self, cmd: &Command) {
        // Argument literals, including any operand bash would have taken out of
        // a `>&-word` redirect. See `redirect::command_arg_literals`.
        //
        // This runs before the no-arguments check because the operand can *be*
        // the command name: `>&-danger` has no arguments of its own, and bash
        // closes stdout and runs `danger`.
        let redirect::CommandLine {
            arguments: arg_literals,
            comment,
        } = redirect::command_line(cmd, self.source);
        // A comment runs to the end of the line, so it silences what follows in
        // this command *and* every later one — `cat x >&-#foo | rm -rf zzz`
        // runs no `rm`, and demanding a write for it is a deny no rule lifts.
        if let Some(range) = comment.clone() {
            self.comment = Some(range);
        }
        // The operand bash lexed out of a `>&-word` is an argument, and an
        // argument's interior is walked: `cat >&-$(rm -rf x)` runs the `rm`.
        for word in redirect::recovered_operand_words(cmd, self.source) {
            self.visit_word(word);
            if self.denied.is_some() {
                return;
            }
        }

        // The shell performs a command's redirections whatever shape the
        // command has, so these are derived once, up here, and checked on every
        // path out of this function — including the ones that return before any
        // argument is looked at. Deriving them further down is what let each
        // new short-circuit carry its redirects past the file rules (#53).
        let redirect_accesses =
            redirect::accesses(&cmd.redirects, self.source, self.cwd, comment.as_ref());

        // No command name — an assignment-only command (`FOO=x > log`) or a
        // null one (`> log`). `bash_allowed` is false because no `Bash(...)`
        // rule can name a command that has no name.
        if arg_literals.is_empty() {
            self.check_redirect_accesses(&redirect_accesses, false);
            return;
        }

        // Get command name. Two forms are kept:
        //   - `raw_arg0`: the command as written (e.g. `./tools/rg.cmd`). Used
        //     for Bash rule matching so path-scoped rules like
        //     `Bash(./tools/rg.cmd *)` can compare against the invocation path.
        //   - `cmd_name`: normalized (basename + PATHEXT strip). Used for
        //     parser dispatch, eval/Python short-circuits, and missing-rule
        //     emission (keeps the log's rule suggestion short and name-form).
        let raw_arg0 = match &arg_literals[0] {
            Some(name) => name.clone(),
            None => {
                // Dynamic command name. The matcher walks `items` against
                // the static args only (arg0 is treated as missing); rules
                // starting with a concrete `Arg0(...)` item can't match, but
                // shapes like `Bash(** foo)` can still match if the static
                // args align with the trailing items.
                let dyn_static_args: Vec<String> = arg_literals[1..]
                    .iter()
                    .take_while(|a| a.is_some())
                    .map(|a| a.clone().unwrap())
                    .collect();
                let (_bash_asked, bash_allowed) = self.check_bash_rules(None, &dyn_static_args);
                if self.denied.is_some() {
                    return;
                }
                if !bash_allowed {
                    self.unmatched.push("Bash(<dynamic command>)".to_string());
                }
                self.check_redirect_accesses(&redirect_accesses, bash_allowed);
                return;
            }
        };
        let cmd_name = cmd_parser::normalize_cmd_name(&raw_arg0).to_string();

        // Static arg list — only consecutive static arg literals after arg0.
        let static_args: Vec<String> = arg_literals[1..]
            .iter()
            .take_while(|a| a.is_some())
            .map(|a| a.clone().unwrap())
            .collect();

        // Run Bash deny/ask/allow matching. Deny short-circuits the whole
        // command; allow enables secondary-demand suppression downstream.
        let (bash_asked, bash_allowed) = self.check_bash_rules(Some(&raw_arg0), &static_args);
        if self.denied.is_some() {
            return;
        }

        // eval — always ask (unless a Bash allow rule explicitly covers it).
        // Its redirects are still checked: `eval x > vault/pwned` writes the
        // file whether or not the code being evaluated can be analyzed.
        if cmd_name == "eval" {
            if !bash_allowed {
                self.unmatched
                    .push("Bash(eval ...) -- cannot statically analyze eval".to_string());
            }
            self.check_redirect_accesses(&redirect_accesses, bash_allowed);
            return;
        }

        // Extract file accesses from well-known command semantics (clap-based parsers)
        let cmd_parse_result =
            cmd_parser::parse_file_accesses(&cmd_name, &arg_literals[1..], self.cwd);
        let (cmd_accesses, parse_failed, inline_script_start, file_only_override, effective_cmd) =
            match cmd_parse_result {
                CmdParseResult::Parsed(cfa) => {
                    let script_start = cfa.inline_script_start;
                    let file_only = cfa.file_only;
                    let eff = cfa.effective_cmd_name;
                    let accesses = cfa
                        .reads
                        .into_iter()
                        .map(|scope| FileAccess::scoped(scope, AccessKind::Read))
                        .chain(
                            cfa.writes
                                .into_iter()
                                .map(|scope| FileAccess::scoped(scope, AccessKind::Write)),
                        )
                        .collect::<Vec<_>>();
                    (accesses, false, script_start, file_only, eff)
                }
                CmdParseResult::ParseFailed {
                    cmd_name: cn,
                    message,
                } => {
                    if !bash_allowed {
                        // Use raw arg0 (not normalized) so the diagnostic
                        // shows the user's actual command, e.g.
                        // `./tools/rg.cmd -l …` rather than `rg -l …`.
                        let cmd_str = std::iter::once(raw_arg0.as_str())
                            .chain(static_args.iter().map(|s| s.as_str()))
                            .collect::<Vec<_>>()
                            .join(" ");
                        self.unmatched.push(format!(
                            "Bash({cmd_str}) -- failed to parse arguments for `{cn}`: {message}"
                        ));
                    }
                    (vec![], true, None, None, None)
                }
            };

        // The effective command name for Python analysis and is_file_only_command.
        // For wrapper commands like `uv run python -c ...`, this is `python`.
        let effective = effective_cmd.as_deref().unwrap_or(&cmd_name);

        // Attempt Python AST analysis for python -c inline scripts.
        // If the script can be fully analyzed, its file accesses are appended to
        // cmd_accesses and the Bash() rule requirement is suppressed.
        let mut python_analyzed = false;
        let mut cmd_accesses = cmd_accesses;
        if cmd_parser::is_python_cmd(effective) && !bash_asked {
            if let Some(script_idx) = inline_script_start {
                // inline_script_start is 0-based into args-after-cmd-name.
                // arg_literals[0] is the cmd name, so script text is at [script_idx + 1].
                if let Some(Some(script_text)) = arg_literals.get(script_idx + 1) {
                    if let PythonAnalysis::Analyzed { accesses } =
                        python_ast::analyze_python_script(script_text, self.cwd)
                    {
                        cmd_accesses.extend(accesses);
                        python_analyzed = true;
                    }
                }
            }
        }

        // Check all file accesses. A matching Bash allow rule suppresses ask-
        // and missing-allow-driven `unmatched` pushes; file Deny rules still
        // fire because `check_file_access` runs the deny scan unconditionally.
        for access in redirect_accesses.iter().chain(cmd_accesses.iter()) {
            self.check_file_access(access, bash_allowed);
            if self.denied.is_some() {
                return;
            }
        }

        // For file-only commands (mkdir, touch, rm, cp, …), the file access rules are
        // sufficient — no separate Bash() rule is needed, provided:
        //   1. the command has at least one resolved file access to gate it,
        //   2. all arguments are static (no dynamic args that could hide unchecked paths), and
        //   3. the parser didn't fail (we trust the extracted accesses).
        // Similarly, when Python AST analysis succeeded, the Bash() rule is suppressed.
        if !bash_allowed && !parse_failed {
            // The command's environment is a second input channel, and argv
            // does not describe it. An assignment to a variable that is not
            // provably inert can make an otherwise file-only invocation run an
            // arbitrary program — `GIT_EXTERNAL_DIFF=./evil.sh git diff` — so
            // it is not file-only, exactly as `find -exec` is not. The list is
            // of inert names rather than dangerous ones because no enumeration
            // of dangerous names terminates; see `env_prefix`.
            let unmodelled_env: Vec<&str> = cmd
                .assignments
                .iter()
                .map(|a| a.name.as_str())
                .filter(|name| !env_prefix::is_inert(name))
                .collect();

            let has_file_accesses = !redirect_accesses.is_empty() || !cmd_accesses.is_empty();
            let has_dynamic_args = arg_literals[1..].iter().any(|a| a.is_none());
            let can_skip_ignoring_env = match file_only_override {
                // Parser explicitly declared this invocation's effects.
                // Trust it even with zero file accesses (e.g. read-only git
                // subcommands), but still require static args.
                Some(true) => !has_dynamic_args && !bash_asked,
                // Parser says there are non-file side effects (e.g. network).
                Some(false) => false,
                // Legacy path: use is_file_only_command() and require at
                // least one file access as a guard.
                None => {
                    file_access::is_file_only_command(effective)
                        && has_file_accesses
                        && !has_dynamic_args
                        && !bash_asked
                }
            } || (python_analyzed && !bash_asked);

            // Only when the prefix is what tipped the decision does the
            // suggestion say so. `SKULD_LABELS=… cargo test` needed its
            // `Bash(cargo *)` rule anyway and keeps the plain message.
            let env_forced_the_rule = can_skip_ignoring_env && !unmodelled_env.is_empty();
            let can_skip = can_skip_ignoring_env && unmodelled_env.is_empty();

            if !can_skip {
                // Build a name-form suggestion filter: `Arg0::Name(stripped
                // basename of raw_arg0)` + `Arg` items for each static arg,
                // optionally truncated at the inline-script index with a
                // trailing `MatchZeroOrMore`. Name form is the friendliest
                // rule shape to copy-paste into settings.json.
                let arg0_name = cmd_name.clone();
                let mut items: Vec<BashFilterItem> =
                    vec![BashFilterItem::Arg0(Arg0Pattern::Name(arg0_name))];
                let (arg_count, trailing_wildcard) = match inline_script_start {
                    // `idx` is 0-based into args (without arg0). Truncate
                    // before the inline script text and emit a wildcard so
                    // the suggestion reads e.g. `python -c *`.
                    Some(idx) => (idx.min(static_args.len()), true),
                    None => (static_args.len(), false),
                };
                for s in &static_args[..arg_count] {
                    items.push(BashFilterItem::Arg(s.clone()));
                }
                if trailing_wildcard {
                    items.push(BashFilterItem::MatchZeroOrMore);
                }
                let filter = BashFilter::from_items(items);
                // `missing_rules` holds pasteable rules and nothing else; the
                // explanation is advisory and belongs in `notes`.
                self.unmatched.push(filter.to_rule_string());
                if env_forced_the_rule {
                    self.notes.push(format!(
                        "environment assignment(s) {} can change what this command runs",
                        unmodelled_env.join(", "),
                    ));
                }
            }
        }
    }

    /// Check a command's redirect-derived accesses, stopping at the first deny.
    fn check_redirect_accesses(&mut self, accesses: &[FileAccess], bash_allowed: bool) {
        for access in accesses {
            self.check_file_access(access, bash_allowed);
            if self.denied.is_some() {
                return;
            }
        }
    }

    /// Check file access against Read/Write/Edit rules.
    ///
    /// Edit-over-Write fallback: for `AccessKind::Write`, each bucket (deny, ask,
    /// allow) is tested first against `write.<bucket>` and then against
    /// `edit.<bucket>`. `Edit(pat)` therefore also allows/denies/asks writes —
    /// but not vice versa. The fallback is an intentional asymmetry; see
    /// CLAUDE.md conventions.
    ///
    /// `suppress_unmatched`: when true, ask-matches and missing-allow results
    /// do not push to `self.unmatched` (used when a Bash allow rule already
    /// covers the owning command). Deny rules still fire unconditionally and
    /// `matched_allow` still records matching allow rules for the log.
    fn check_file_access(&mut self, access: &FileAccess, suppress_unmatched: bool) {
        if self.denied.is_some() {
            return;
        }

        // Canonicalize the query path(s) before matching against rules
        let scope = access.scope.canonicalized();
        let shown = scope.display();

        // Check deny first (Edit fallback for Write) — always runs, even when
        // suppressing, because file Deny is authoritative. Deny and ask scan
        // over-approximately: a rule fires if it *could* reach any path the
        // access touches.
        let deny_matched: Option<String> = match access.kind {
            AccessKind::Read => find_could_match(&self.perms.read.deny, &scope),
            AccessKind::Write => find_could_match(&self.perms.write.deny, &scope)
                .or_else(|| find_could_match(&self.perms.edit.deny, &scope)),
        };
        if let Some(rule_str) = deny_matched {
            self.matched_deny.push(rule_str);
            self.deny(format!(
                "File access '{}' ({:?}) matched deny rule",
                shown, access.kind
            ));
            return;
        }

        // Check ask rules — force ask even if allowed (Edit fallback for Write)
        let ask_matched = match access.kind {
            AccessKind::Read => find_could_match(&self.perms.read.ask, &scope).is_some(),
            AccessKind::Write => {
                find_could_match(&self.perms.write.ask, &scope).is_some()
                    || find_could_match(&self.perms.edit.ask, &scope).is_some()
            }
        };
        if ask_matched {
            if !suppress_unmatched {
                self.unmatched.push(rule_suggestion(access.kind, &scope));
            }
            return;
        }

        // Check allow (Edit fallback for Write). The allow scan is
        // under-approximating: a rule counts only when it provably covers
        // every path the access touches. Anything unproven falls through to
        // the push below, which is what turns an unsatisfiable access — an
        // unresolved path, a symlink-following walk — into an ask.
        let allow_matched: Option<String> = match access.kind {
            AccessKind::Read => find_covers(&self.perms.read.allow, &scope),
            AccessKind::Write => find_covers(&self.perms.write.allow, &scope)
                .or_else(|| find_covers(&self.perms.edit.allow, &scope)),
        };
        if let Some(rule_str) = allow_matched {
            self.matched_allow.push(rule_str);
        } else if !suppress_unmatched {
            self.unmatched.push(rule_suggestion(access.kind, &scope));
        }
    }

    /// Scan Bash allow/ask/deny rules against the given command invocation.
    ///
    /// `raw_arg0` is `Some(name)` for a statically-resolvable command name (as
    /// written, not normalized — `./tools/rg.cmd` rather than `rg`), or `None`
    /// when the arg0 was dynamic. In the dynamic case, only universal wildcard
    /// rules (`Bash(*)` / `Bash(**)`) can match.
    ///
    /// Returns `(bash_asked, bash_allowed)`. If a deny rule matches, records
    /// it via `self.deny(...)` and `self.matched_deny`; callers should check
    /// `self.denied` after the call. Pushes the first matching allow rule's
    /// string into `self.matched_allow` (mirroring the pre-refactor `.any`
    /// short-circuit). When `bash_asked` is true, the allow scan is skipped
    /// entirely — so no allow rule is recorded in that case, matching prior
    /// behavior.
    fn check_bash_rules(&mut self, raw_arg0: Option<&str>, args: &[String]) -> (bool, bool) {
        let cwd = self.cwd;
        let test = |f: &BashFilter| match raw_arg0 {
            Some(a) => f.matches(a, args, cwd),
            None => f.matches_dynamic_arg0(args, cwd),
        };

        for filter in &self.perms.bash.deny {
            if test(filter) {
                let rule_str = filter.to_rule_string();
                self.matched_deny.push(rule_str);
                self.deny(match raw_arg0 {
                    None => "Dynamic command name matched deny rule".to_string(),
                    Some(a) => {
                        let cmd_str = std::iter::once(a)
                            .chain(args.iter().map(|s| s.as_str()))
                            .collect::<Vec<_>>()
                            .join(" ");
                        format!("Command '{cmd_str}' matched deny rule")
                    }
                });
                return (false, false);
            }
        }

        let asked = self.perms.bash.ask.iter().any(&test);

        let mut allowed = false;
        if !asked {
            for f in &self.perms.bash.allow {
                if test(f) {
                    self.matched_allow.push(f.to_rule_string());
                    allowed = true;
                    break;
                }
            }
        }
        (asked, allowed)
    }

    /// Does a comment cover this offset?
    fn is_commented_out(&self, position: usize) -> bool {
        self.comment
            .as_ref()
            .is_some_and(|range| range.contains(&position))
    }

    /// `source[start..end]`, when there is a source and the range is valid.
    fn slice(&self, start: usize, end: usize) -> Option<&'a str> {
        self.source.and_then(|source| source.get(start..end))
    }

    /// Walk a nested command with the source it was parsed from.
    ///
    /// thaum parses a substitution's body separately, so the spans inside it
    /// restart at zero. Walking those with the outer command's text would read
    /// another command's bytes, so the source is re-based here — and set to
    /// `None` where the body cannot be located, which the redirect classifier
    /// answers by over-approximating rather than by guessing.
    fn visit_nested(&mut self, stmts: &[Statement], body: Option<&'a str>) {
        let outer = (self.source, self.comment.take());
        self.source = body;
        // A comment inside the substitution ends the substitution's line, and
        // one outside it never reached here.
        for stmt in stmts {
            self.visit_statement(stmt);
        }
        (self.source, self.comment) = outer;
    }

    /// The funnel's second storey: descend a fragment into any nested
    /// substitution it carries.
    ///
    /// **This match is deliberately exhaustive — do not add a `_ => {}` arm.**
    /// Listing every variant makes a new `Fragment` in thaum a compile error
    /// here rather than a silently unwalked shape.
    ///
    /// Some variants are leaves in thaum's grammar and some are leaves only
    /// because thaum does not parse their interior; the difference matters and
    /// is noted per arm.
    fn check_fragment_command_subs(&mut self, fragment: &Fragment, body: Option<&'a str>) {
        if self.denied.is_some() {
            return;
        }
        match fragment {
            Fragment::CommandSubstitution(stmts) => {
                self.visit_nested(stmts, body);
            }
            // Carriers of further fragments — recurse.
            Fragment::DoubleQuoted(inner) | Fragment::BashLocaleQuoted(inner) => {
                for f in inner {
                    self.check_fragment_command_subs(f, body);
                }
            }
            Fragment::BashBraceExpansion(BraceExpansionKind::List(alternatives)) => {
                for alternative in alternatives {
                    for f in alternative {
                        self.check_fragment_command_subs(f, body);
                    }
                }
            }
            // `${x:-word}` and friends. thaum currently stores the argument's
            // interior as a single `Literal` rather than parsing it, so today
            // this arm finds nothing for `${Y:-$(rm -rf x)}` — that family is
            // unreached and tracked in #69. The arm is here so the descent is
            // correct the moment thaum parses the argument, rather than needing
            // to be rediscovered then.
            Fragment::Parameter(ParameterExpansion::Complex {
                argument: Some(word),
                ..
            }) => {
                for f in &word.parts {
                    self.check_fragment_command_subs(f, body);
                }
            }
            // True leaves: no nested fragments in the grammar.
            Fragment::Literal(_)
            | Fragment::SingleQuoted(_)
            | Fragment::BashAnsiCQuoted(_)
            | Fragment::Glob(_)
            | Fragment::TildePrefix(_)
            | Fragment::Parameter(ParameterExpansion::Simple(_))
            | Fragment::Parameter(ParameterExpansion::Complex { argument: None, .. })
            | Fragment::BashBraceExpansion(BraceExpansionKind::Sequence { .. }) => {}
            // Leaves only because thaum keeps their interior as a string:
            // `$(( $(...) ))` and `@( $(...) )` are unreachable from here at
            // any call depth. Tracked in #69 with the `${x:-...}` family.
            Fragment::ArithmeticExpansion(_) | Fragment::BashExtGlob { .. } => {}
        }
    }
}

/// Scan a bucket of path filters for one that *could* reach any path in
/// `scope`; return its rule string form if found. The deny/ask direction.
fn find_could_match<F: PathFilter>(bucket: &[F], scope: &AccessScope) -> Option<String> {
    bucket
        .iter()
        .find(|f| f.could_match(scope))
        .map(|f| f.to_rule_string())
}

/// Scan a bucket of path filters for one that provably covers every path in
/// `scope`; return its rule string form if found. The allow direction.
fn find_covers<F: PathFilter>(bucket: &[F], scope: &AccessScope) -> Option<String> {
    bucket
        .iter()
        .find(|f| f.covers(scope))
        .map(|f| f.to_rule_string())
}

/// The rule a user would add to satisfy an unmatched access. For a subtree the
/// suggestion is `Read(D/**)`, which also covers the subtree root.
///
/// A symlink-following walk has no such rule: it can reach outside the tree it
/// names, so `covers` rejects every path pattern. Naming a `Read`/`Write` rule
/// there would send the user round a loop — they add it, rerun, and are asked
/// again — so that case names `Bash(...)`, the only rule that does resolve it.
/// It must not offer `display()`'s `<dir>/**+symlinks` either: that is a label,
/// not a glob any rule can use.
fn rule_suggestion(kind: AccessKind, scope: &AccessScope) -> String {
    let kind_name = match kind {
        AccessKind::Read => "Read",
        AccessKind::Write => "Write",
    };
    if let AccessScope::UnboundedSubtree(dir) = scope {
        let dir = dir.trim_end_matches('/');
        return format!(
            "Bash(...) -- this {} of {dir} follows symlinks out of the tree, so no \
             {kind_name} rule can cover it; allow the command itself instead",
            kind_name.to_lowercase(),
        );
    }
    format!("{kind_name}({})", scope.display())
}

#[cfg(test)]
mod apply_mode_tests {
    use super::*;

    fn ask_result() -> CheckResult {
        CheckResult {
            decision: Decision::Ask,
            matched_allow: vec![],
            matched_deny: vec![],
            missing_rules: vec!["Bash(foo)".into(), "Bash(bar)".into()],
            custom_reason: None,
            notes: vec![],
        }
    }

    fn allow_result() -> CheckResult {
        CheckResult {
            decision: Decision::Allow,
            matched_allow: vec!["Bash(ls *)".into()],
            matched_deny: vec![],
            missing_rules: vec![],
            custom_reason: None,
            notes: vec![],
        }
    }

    fn deny_result(reason: &str) -> CheckResult {
        CheckResult {
            decision: Decision::Deny(reason.into()),
            matched_allow: vec![],
            matched_deny: vec!["Bash(rm *)".into()],
            missing_rules: vec![],
            custom_reason: None,
            notes: vec![],
        }
    }

    #[test]
    fn ask_to_allow_in_bypass() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::BypassPermissions));
        assert_eq!(out.decision, Decision::Allow);
    }

    #[test]
    fn ask_to_allow_in_auto() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::Auto));
        assert_eq!(out.decision, Decision::Allow);
    }

    #[test]
    fn ask_to_deny_in_dont_ask() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::DontAsk));
        match out.decision {
            Decision::Deny(reason) => {
                assert!(
                    reason.starts_with("dontAsk mode: command requires rule(s)"),
                    "unexpected reason: {reason}",
                );
                assert!(reason.contains("Bash(foo)"));
                assert!(reason.contains("Bash(bar)"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn ask_preserved_in_default_modes() {
        for mode in [
            None,
            Some(PermissionMode::Default),
            Some(PermissionMode::Plan),
            Some(PermissionMode::AcceptEdits),
        ] {
            let out = apply_permission_mode(ask_result(), mode);
            assert_eq!(out.decision, Decision::Ask, "mode: {mode:?}");
        }
    }

    #[test]
    fn allow_preserved_in_every_mode() {
        for mode in [
            None,
            Some(PermissionMode::Default),
            Some(PermissionMode::Plan),
            Some(PermissionMode::AcceptEdits),
            Some(PermissionMode::Auto),
            Some(PermissionMode::BypassPermissions),
            Some(PermissionMode::DontAsk),
        ] {
            let out = apply_permission_mode(allow_result(), mode);
            assert_eq!(out.decision, Decision::Allow, "mode: {mode:?}");
        }
    }

    #[test]
    fn deny_preserved_in_every_mode_including_bypass() {
        for mode in [
            None,
            Some(PermissionMode::Default),
            Some(PermissionMode::Plan),
            Some(PermissionMode::AcceptEdits),
            Some(PermissionMode::Auto),
            Some(PermissionMode::BypassPermissions),
            Some(PermissionMode::DontAsk),
        ] {
            let out = apply_permission_mode(deny_result("no"), mode);
            assert!(matches!(out.decision, Decision::Deny(_)), "mode: {mode:?}");
        }
    }

    #[test]
    fn missing_rules_preserved_after_ask_to_allow_transform() {
        let out = apply_permission_mode(ask_result(), Some(PermissionMode::BypassPermissions));
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(out.missing_rules, vec!["Bash(foo)", "Bash(bar)"]);
    }

    #[test]
    fn custom_reason_preserved_through_transform() {
        let mut r = ask_result();
        r.custom_reason = Some("Shell command could not be parsed".into());
        let out = apply_permission_mode(r, Some(PermissionMode::BypassPermissions));
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(
            out.custom_reason.as_deref(),
            Some("Shell command could not be parsed"),
        );
    }

    #[test]
    fn idempotent_in_bypass() {
        let once = apply_permission_mode(ask_result(), Some(PermissionMode::BypassPermissions));
        let twice = apply_permission_mode(once.clone(), Some(PermissionMode::BypassPermissions));
        assert_eq!(once, twice);
    }

    #[test]
    fn idempotent_in_dont_ask() {
        let once = apply_permission_mode(ask_result(), Some(PermissionMode::DontAsk));
        let twice = apply_permission_mode(once.clone(), Some(PermissionMode::DontAsk));
        assert_eq!(once, twice);
    }
}

#[cfg(test)]
mod fragment_descent_tests {
    use super::*;
    use crate::permission;
    use crate::settings::Permissions;
    use thaum::span::Span;

    fn deny_rm() -> ParsedPermissions {
        permission::parse_rules(
            &Permissions {
                deny: vec!["Bash(rm *)".to_string()],
                ..Default::default()
            },
            "/tmp",
            "/tmp",
        )
    }

    fn word(parts: Vec<Fragment>) -> Word {
        Word {
            parts,
            span: Span::new(0, 0),
        }
    }

    /// `rm -rf /tmp/zzz` as a statement list, for embedding in a fragment.
    fn rm_statements() -> Vec<Statement> {
        let program = thaum::parse_with("rm -rf /tmp/zzz", thaum::Dialect::Bash).unwrap();
        program.statements
    }

    fn program_running(parts: Vec<Fragment>) -> Program {
        // `cat <word>` — the word carries the fragment under test.
        let cmd = Command {
            assignments: vec![],
            arguments: vec![
                Argument::Word(word(vec![Fragment::Literal("cat".to_string())])),
                Argument::Word(word(parts)),
            ],
            redirects: vec![],
            span: Span::new(0, 0),
        };
        Program {
            statements: vec![Statement {
                expression: Expression::Command(cmd),
                mode: ExecutionMode::Sequential,
                span: Span::new(0, 0),
            }],
            span: Span::new(0, 0),
        }
    }

    /// The `Parameter { argument }` arm cannot be reached through the pinned
    /// thaum revision, which builds `${Y:-$(...)}`'s interior as a flat
    /// `Literal`. Upstream parses it, so the arm goes live when the pin moves.
    /// Building the node by hand proves the descent is correct now rather than
    /// leaving it unverifiable until then.
    #[test]
    fn parameter_argument_descent_reaches_a_substitution() {
        let fragment = Fragment::Parameter(ParameterExpansion::Complex {
            name: "Y".to_string(),
            operator: Some(ParamOp::Default),
            argument: Some(Box::new(word(vec![Fragment::CommandSubstitution(
                rm_statements(),
            )]))),
        });
        // Hand-built nodes carry no source text, and none is needed: the deny
        // comes from the command name inside the substitution, not from how
        // any character was written.
        let result = check_program(&program_running(vec![fragment]), "", &deny_rm(), "/tmp");
        assert!(
            matches!(result.decision, Decision::Deny(_)),
            "Parameter argument descent did not reach the substitution: {result:?}",
        );
    }

    /// The same, nested one level further: `"pre${Y:-$(rm ...)}post"`.
    #[test]
    fn parameter_argument_descent_works_inside_double_quotes() {
        let inner = Fragment::Parameter(ParameterExpansion::Complex {
            name: "Y".to_string(),
            operator: Some(ParamOp::Default),
            argument: Some(Box::new(word(vec![Fragment::CommandSubstitution(
                rm_statements(),
            )]))),
        });
        let fragment = Fragment::DoubleQuoted(vec![
            Fragment::Literal("pre".to_string()),
            inner,
            Fragment::Literal("post".to_string()),
        ]);
        // Hand-built nodes carry no source text, and none is needed: the deny
        // comes from the command name inside the substitution, not from how
        // any character was written.
        let result = check_program(&program_running(vec![fragment]), "", &deny_rm(), "/tmp");
        assert!(
            matches!(result.decision, Decision::Deny(_)),
            "descent failed inside double quotes: {result:?}",
        );
    }
}
