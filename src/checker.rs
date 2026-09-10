use thaum::ast::*;
use thaum::visit::Visit;

use crate::cmd_parser::{self, CmdParseResult};
use crate::file_access::{self, AccessKind, AccessScope, FileAccess};
use crate::filter::{Arg0Pattern, BashFilter, BashFilterItem, Filter, PathFilter};
use crate::permission::ParsedPermissions;
use crate::permission_mode::PermissionMode;
use crate::python_ast::{self, PythonAnalysis};

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
            Decision::Deny(reason)
        }
        (other, _) => other,
    };
    result
}

/// Top-level entry point: check a parsed program against permission rules.
pub fn check_program(program: &Program, perms: &ParsedPermissions, cwd: &str) -> CheckResult {
    let mut checker = PermissionChecker {
        perms,
        cwd,
        unmatched: Vec::new(),
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
        unmatched: Vec::new(),
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
    unmatched: Vec<String>,
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
        if self.denied.is_some() {
            return;
        }
        self.check_command(cmd);
        // Walk arguments for embedded process substitutions / command substitutions.
        // Don't call walk_command — we already handled redirects inside check_command.
        for arg in &cmd.arguments {
            self.visit_argument(arg);
        }
    }

    fn visit_redirect(&mut self, redirect: &'ast Redirect) {
        // Handles redirects for compound / function-def contexts (e.g.
        // `{ ...; } > /log`). Simple-command redirects are handled inside
        // `check_command` via `extract_redirect_accesses`. Compound redirects
        // are not bound to a single command, so no Bash allow rule can
        // suppress them.
        if self.denied.is_some() {
            return;
        }
        for access in accesses_for_redirect(redirect, self.cwd) {
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
                for stmt in body {
                    self.visit_statement(stmt);
                }
            }
            Argument::Word(w) => {
                self.check_word_command_subs(w);
            }
        }
    }
}

// ─── Domain logic ────────────────────────────────────────────────────────────

impl PermissionChecker<'_> {
    fn finalize(mut self) -> CheckResult {
        self.unmatched.sort();
        self.unmatched.dedup();
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
        // Assignment-only command (no command name)
        if cmd.arguments.is_empty() {
            return;
        }

        // Argument literals, including any operand bash would have taken out of
        // a `>&-word` redirect. See `command_arg_literals`.
        let arg_literals: Vec<Option<String>> = command_arg_literals(cmd);

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
                for access in extract_redirect_accesses(&cmd.redirects, self.cwd) {
                    self.check_file_access(&access, bash_allowed);
                    if self.denied.is_some() {
                        return;
                    }
                }
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
        if cmd_name == "eval" {
            if !bash_allowed {
                self.unmatched
                    .push("Bash(eval ...) -- cannot statically analyze eval".to_string());
            }
            return;
        }

        // Extract file accesses from redirects
        let redirect_accesses = extract_redirect_accesses(&cmd.redirects, self.cwd);

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
            let has_file_accesses = !redirect_accesses.is_empty() || !cmd_accesses.is_empty();
            let has_dynamic_args = arg_literals[1..].iter().any(|a| a.is_none());
            let can_skip = match file_only_override {
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
                self.unmatched.push(filter.to_rule_string());
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

    /// Walk word fragments for command substitutions.
    fn check_word_command_subs(&mut self, word: &Word) {
        for fragment in &word.parts {
            self.check_fragment_command_subs(fragment);
        }
    }

    fn check_fragment_command_subs(&mut self, fragment: &Fragment) {
        if self.denied.is_some() {
            return;
        }
        match fragment {
            Fragment::CommandSubstitution(stmts) => {
                for stmt in stmts {
                    self.visit_statement(stmt);
                }
            }
            Fragment::DoubleQuoted(inner) => {
                for f in inner {
                    self.check_fragment_command_subs(f);
                }
            }
            _ => {}
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

// ─── Redirect file access extraction ─────────────────────────────────────────

/// The file accesses one redirect performs.
///
/// Empty means the redirect opens no file, and every such arm says why rather
/// than defaulting. A blanket "fd duplication" arm is what let `>&FILE` reach a
/// file unchecked, and folding `<>` in with the write-only forms is what kept
/// `Read` deny rules from firing on it.
///
/// A redirect can name a file in more than one way, hence the `Vec`: `<>` opens
/// one path for both reading and writing.
fn accesses_for_redirect(redirect: &Redirect, cwd: &str) -> Vec<FileAccess> {
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
            if !redirects_stdout || names_a_descriptor(w) {
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
/// The move form is the one worth spelling out, because it only became
/// load-bearing when `>&FILE` started being treated as a write. Reading its
/// trailing `-` as part of a filename turns `>&2-` into a write to a file
/// called `2-`, which a `Deny(Write(...))` over the directory then blocks — a
/// false deny on a valid command, and no rule the user adds can lift it.
///
/// A leading `-` is *not* this: `>&-2` opens a file called `-2`, because the
/// word is neither digits nor `-`.
///
/// A word that does not resolve statically could be any of these or a filename.
/// Of those readings only the file one needs checking, so it is not treated as
/// a descriptor.
fn names_a_descriptor(word: &Word) -> bool {
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
    // Every other dash form is a descriptor spec only when written unquoted.
    // Quoting turns it into an ordinary filename, and the two directions are
    // one character apart:
    //
    //   >&-2   close, then `2` as an argument      >&"-2"  writes a file `-2`
    //   >&2-   move fd 2                           >&"2-"  writes a file `2-`
    //   >&x-   "ambiguous redirect", opens nothing >&"x-"  writes a file `x-`
    //
    // A trailing dash makes bash read the whole word as a descriptor spec
    // whatever precedes it, so `>&x-` and `>&2x-` are errors rather than files.
    let dashed = s.starts_with('-') || s.ends_with('-');
    dashed && !word_is_quoted(word)
}

/// Was any part of this word written quoted?
///
/// Only matters for the dash forms above. A word that does not resolve
/// statically never reaches here — `names_a_descriptor` returns early — so the
/// remaining fragment kinds are the literal and quoted ones.
fn word_is_quoted(word: &Word) -> bool {
    !word.parts.iter().all(|f| matches!(f, Fragment::Literal(_)))
}

/// The argument hiding inside a `>&-word` / `<&-word` redirect, and where it
/// starts in the source.
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
/// # This is a workaround, and it has somewhere to go
///
/// The divergence is a lexer bug, tracked as thaum#14
/// (<https://github.com/bindreams/thaum/issues/14>). Reconstructing bash's
/// argument list here means scriptcheck reimplements a lexing rule on top of a
/// parse that got it wrong — worth it while a live read bypass is open, but not
/// where the fix belongs. When thaum#14 lands the operand arrives as an ordinary
/// `Argument`, and this function and its call in `command_arg_literals` should
/// be deleted rather than adapted.
fn closed_descriptor_operand(redirect: &Redirect) -> Option<(usize, String)> {
    let word = match &redirect.kind {
        RedirectKind::DupInput(w) | RedirectKind::DupOutput(w) => w,
        _ => return None,
    };
    // Quoting makes the whole word a filename, so there is no operand to
    // recover: `>&"-2"` writes a file called `-2`.
    if word_is_quoted(word) {
        return None;
    }
    let text = word.try_to_static_string()?;
    let operand = text.strip_prefix('-')?;
    if operand.is_empty() {
        // A bare `>&-` closes the descriptor and names nothing.
        return None;
    }
    // The `-` is one byte, so the operand starts one byte into the word.
    Some((word.span.start.0 + 1, operand.to_string()))
}

/// The arguments bash passes to the command, in source order.
///
/// Ordering matters because position is what gives an operand its meaning:
/// `cp a b` reads `a` and writes `b`, so appending a recovered operand instead
/// of splicing it would invert a read and a write. The splice exists only to
/// work around thaum#14; see `closed_descriptor_operand`. Once that lands, this
/// collapses back to mapping `cmd.arguments`.
///
/// A `>&-word` operand is spliced in at the
/// point the word appears, which is where bash would have put it.
fn command_arg_literals(cmd: &Command) -> Vec<Option<String>> {
    let mut items: Vec<(usize, Option<String>)> = cmd
        .arguments
        .iter()
        .map(|a| (a.span().start.0, a.try_to_static_string()))
        .collect();
    items.extend(
        cmd.redirects
            .iter()
            .filter_map(closed_descriptor_operand)
            .map(|(pos, text)| (pos, Some(text))),
    );
    items.sort_by_key(|(pos, _)| *pos);
    items.into_iter().map(|(_, literal)| literal).collect()
}

fn extract_redirect_accesses(redirects: &[Redirect], cwd: &str) -> Vec<FileAccess> {
    redirects
        .iter()
        .flat_map(|r| accesses_for_redirect(r, cwd))
        .collect()
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
        }
    }

    fn allow_result() -> CheckResult {
        CheckResult {
            decision: Decision::Allow,
            matched_allow: vec!["Bash(ls *)".into()],
            matched_deny: vec![],
            missing_rules: vec![],
            custom_reason: None,
        }
    }

    fn deny_result(reason: &str) -> CheckResult {
        CheckResult {
            decision: Decision::Deny(reason.into()),
            matched_allow: vec![],
            matched_deny: vec!["Bash(rm *)".into()],
            missing_rules: vec![],
            custom_reason: None,
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
