use thaum::ast::*;
use thaum::visit::Visit;

use crate::cmd_parser::{self, CmdParseResult};
use crate::file_access::{self, AccessKind, AccessScope, FileAccess};
use crate::filter::{Arg0Pattern, BashFilter, BashFilterItem, Filter, PathFilter};
use crate::permission::ParsedPermissions;
use crate::permission_mode::PermissionMode;
use crate::python_ast::{self, PythonAnalysis};
use crate::unresolved;

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

        // Two views of the same argument list, deliberately kept separate.
        //
        // `args` is every argument, with unresolvable ones carrying a rendering
        // of the word. It drives file-access analysis, which must see past an
        // unresolvable argument rather than stop at it.
        let args: Vec<cmd_parser::ResolvedArg> =
            cmd.arguments.iter().map(resolve_argument).collect();

        // Get command name. Two forms are kept:
        //   - `raw_arg0`: the command as written (e.g. `./tools/rg.cmd`). Used
        //     for Bash rule matching so path-scoped rules like
        //     `Bash(./tools/rg.cmd *)` can compare against the invocation path.
        //   - `cmd_name`: normalized (basename + PATHEXT strip). Used for
        //     parser dispatch, eval/Python short-circuits, and missing-rule
        //     emission (keeps the log's rule suggestion short and name-form).
        let raw_arg0 = match args[0].as_static() {
            Some(name) => name.to_string(),
            None => {
                // Dynamic command name. The matcher walks `items` against
                // the static args only (arg0 is treated as missing); rules
                // starting with a concrete `Arg0(...)` item can't match, but
                // shapes like `Bash(** foo)` can still match if the static
                // args align with the trailing items.
                let dyn_static_args = bash_rule_args(&args);
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

        let static_args = bash_rule_args(&args);

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
        let cmd_parse_result = cmd_parser::parse_file_accesses(&cmd_name, &args[1..], self.cwd);
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
                if let Some(script_text) = args.get(script_idx + 1).and_then(|a| a.as_static()) {
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
        //   2. every word is statically known, so no unchecked path is hidden, and
        //   3. the parser didn't fail (we trust the extracted accesses).
        // Similarly, when Python AST analysis succeeded, the Bash() rule is suppressed.
        if !bash_allowed && !parse_failed {
            let has_file_accesses = !redirect_accesses.is_empty() || !cmd_accesses.is_empty();
            // Redirect targets count, not just arguments. A file-only command
            // whose reads are satisfied and whose redirect target is unknown was
            // an unconstrained write primitive (#45): nothing was left to object.
            //
            // Parser-derived accesses count for the same reason. Today an
            // unresolved one implies an unresolved argument, so that disjunct is
            // covered by the first; it states the intent rather than relying on
            // the coincidence.
            let unresolved_access = |a: &FileAccess| matches!(a.scope, AccessScope::Unresolved(_));
            let has_unresolved_word = args[1..].iter().any(|a| a.is_unresolved())
                || redirect_accesses.iter().any(unresolved_access)
                || cmd_accesses.iter().any(unresolved_access);
            let file_only_suffices = match file_only_override {
                // Parser explicitly declared this invocation's effects.
                // Trust it even with zero file accesses (e.g. read-only git
                // subcommands), but still require every word to be known.
                Some(true) => !has_unresolved_word && !bash_asked,
                // Parser says there are non-file side effects (e.g. network).
                Some(false) => false,
                // Legacy path: use is_file_only_command() and require at
                // least one file access as a guard.
                None => {
                    file_access::is_file_only_command(effective)
                        && has_file_accesses
                        && !has_unresolved_word
                        && !bash_asked
                }
            };
            // The Python shortcut is a separate route to the same skip, and it
            // needs the same guard: analysing the inline script says nothing
            // about a redirect target or an argument the analysis never saw.
            let python_analysis_suffices = python_analyzed && !bash_asked && !has_unresolved_word;
            let can_skip = file_only_suffices || python_analysis_suffices;

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
/// names, so `covers` rejects every path pattern. Saying `Read(D/**)` there
/// would send the user round a loop — they add the rule, rerun, and are asked
/// again — so that case names the rule shape that does resolve it instead. An
/// unresolved access is in the same position for the same reason.
fn rule_suggestion(kind: AccessKind, scope: &AccessScope) -> String {
    let shown = scope.display();
    if let AccessScope::UnboundedSubtree(dir) = scope {
        return format!(
            "Read({dir}/**) -- follows symlinks out of the tree, so no Read/Write rule \
             can cover it; allow the command with a Bash(...) rule instead",
        );
    }
    if matches!(scope, AccessScope::Unresolved(_)) {
        let verb = match kind {
            AccessKind::Read => "Read",
            AccessKind::Write => "Write",
        };
        return format!(
            "{verb}({shown}) -- the path is not statically known, so no Read/Write rule \
             can cover it; allow the command with a Bash(...) rule instead",
        );
    }
    match kind {
        AccessKind::Read => format!("Read({shown})"),
        AccessKind::Write => format!("Write({shown})"),
    }
}

// ─── Redirect file access extraction ─────────────────────────────────────────

/// One command argument, resolved for file-access analysis.
fn resolve_argument(arg: &Argument) -> cmd_parser::ResolvedArg {
    match arg.try_to_static_string() {
        Some(value) => cmd_parser::ResolvedArg::Static(value),
        None => cmd_parser::ResolvedArg::Unresolved(unresolved::describe_argument(arg)),
    }
}

/// The Bash-rule view of a command's arguments: arg0 excluded, truncated at the
/// first unresolvable argument.
///
/// The truncation is load-bearing and must not be "fixed" to match the
/// file-access view. `BashFilter::matches` aligns its items positionally, so
/// substituting a placeholder for an unresolvable argument would silently
/// change which `Bash(...)` rules match a command.
fn bash_rule_args(args: &[cmd_parser::ResolvedArg]) -> Vec<String> {
    args[1..]
        .iter()
        .map_while(|a| a.as_static().map(str::to_string))
        .collect()
}

/// The file accesses one redirect performs.
///
/// Empty means the redirect opens no file. Every such case is spelled out with
/// its reason rather than defaulted: a blanket "fd duplication" arm is what hid
/// `>&FILE` (#48), and classifying `<>` as write-only is what hid #49.
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
        // `<&word` requires digits or `-` (Bash §3.6.8); any other word is a
        // redirection error, not a file open. The file special case below is
        // stated for output only.
        RedirectKind::DupInput(_) => return Vec::new(),
        RedirectKind::DupOutput(w) => {
            // Bash §3.6.8: "if n is omitted, and word does not expand to one or
            // more digits or '-', the standard output and standard error are
            // redirected" — that is a file write. With n present, or a word
            // that duplicates, nothing is opened.
            if redirect.fd.is_some() || duplicates_a_descriptor(w) {
                return Vec::new();
            }
            (w, &[Write])
        }
    };

    let scope = match word.try_to_static_string() {
        Some(path) => AccessScope::Exact(file_access::resolve_path(&path, cwd)),
        // Ask, don't drop: an unknown target matches no deny rule and satisfies
        // no allow rule, so it always surfaces.
        None => AccessScope::Unresolved(unresolved::describe_word(word)),
    };
    kinds
        .iter()
        .map(|kind| FileAccess::scoped(scope.clone(), *kind))
        .collect()
}

/// Does this `>&word` target duplicate or close a descriptor instead of naming
/// a file?
///
/// Only a statically known all-digit word or `-` does. An unresolvable word
/// might be either, and of the two readings only the file one needs checking.
fn duplicates_a_descriptor(word: &Word) -> bool {
    match word.try_to_static_string() {
        Some(s) => s == "-" || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
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
