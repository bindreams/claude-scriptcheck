# claude-scriptcheck

Permission checker for Claude Code pre-tool-use hooks.
Checks Bash commands (AST-aware, parsed with [thaum](https://github.com/bindreams/thaum)) and file-access tools (Read, Write, Edit, Grep, Glob) against permission rules in Claude's `settings.json`.

## Build & test

```sh
cargo build              # debug build
cargo build --release    # release build (thin LTO, opt-level 2)
cargo test               # all unit + integration tests
cargo install --git https://github.com/bindreams/claude-scriptcheck.git  # install/upgrade
```

## Source map

| File                 | Role                                                                                                               |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `src/lib.rs`         | Library crate root. Re-exports all modules so they are usable without spawning the binary.                         |
| `src/main.rs`        | Binary: CLI routing (clap), hook-mode dispatch (Bash/Monitor/Grep/Glob/Read/Write/Edit), I/O (stdin JSON → decision JSON). |
| `src/cli.rs`         | Subcommand implementations: `install`, `uninstall`, `check`, `log`, `log-path`, `upgrade`. `VerdictFilter` type.   |
| `src/checker.rs`     | Core logic. `check_program()` for Bash AST, `check_file_accesses()` for non-Bash tools. Returns `CheckResult`. `find_match<F: PathFilter>()` is the generic per-verdict scan. End-stage `apply_permission_mode()` transforms verdicts per mode. |
| `src/filter.rs`      | `Filter` / `PathFilter` traits, `RuleSet<F>` bucketed by verdict, `Verdict` enum, `impl_filter!` macro. Sub-modules under `src/filter/`. |
| `src/filter/bash.rs` | `BashFilter` — command-token glob filter. Owns `matches(&[String])` and `match_tokens` / `token_matches` helpers. |
| `src/filter/path.rs` | `ReadFilter`, `WriteFilter`, `EditFilter` — single-field newtypes over canonical glob patterns. Debug-assert canonical form on construction. |
| `src/permission.rs`  | Parses rule strings (`Bash(cmd *)`, `Read(glob)`, etc.) into `ParsedPermissions`. `parse_rules`/`parse_single_rule` → `ParsedFilter` variants. `load_perms()` composes `settings::load_settings` + parse + mode-specific synthetic rule injection. |
| `src/permission_mode.rs` | `PermissionMode` enum with `ValueEnum` (clap) and `from_hook_str` for the hook JSON field.                     |
| `src/file_access.rs` | Maps well-known commands to file-access semantics (read/write args, redirects). ~25 unit tests.                    |
| `src/hook.rs`        | `HookInput` / `HookOutput` serde structs for JSON protocol with Claude Code.                                       |
| `src/settings.rs`    | Loads and merges permission rules + `additionalDirectories` (both nested inside `permissions` and top-level) from settings files. Returns `LoadedSettings`. `resolve_one_rule` normalizes separators before the 4-tier prefix dispatch so backslash-written paths route correctly. |
| `src/logging.rs`     | Appends decisions to platform-specific log file. Read-back helpers: `split_documents()`, `extract_verdict()`.       |
| `src/path_util.rs`   | Cross-platform path helpers: `is_absolute()`, `normalize_separators()`, `is_filesystem_root()`.                    |
| `src/env_hooks.rs`   | Test-isolation env-var hooks: `hook_home()` overrides `dirs::home_dir()` for the hook dispatch path; `log_path_override()` overrides the log file location. |
| `src/python_ast.rs`  | Python AST analysis for `python -c` inline scripts. Parses Python, extracts file accesses, detects unsafe patterns.|
| `src/cmd_parser/git.rs` | Git subcommand parser. Dispatches on subcommand, emits Write(.git) for local ops, file_only=false for network ops.|
| `src/cmd_parser/wrappers.rs` | Wrapper command parsers (e.g. `uv run`). Strips wrapper flags, dispatches to inner command's parser.         |
| `tests/suite/`       | Integration tests: logic tests call the library API directly; binary I/O tests invoke the compiled binary.         |

## Key types

```
Decision        = Allow | Deny(reason) | Ask
CheckResult     { decision, matched_allow, matched_deny, missing_rules: Vec<String>, custom_reason: Option<String> }
    // missing_rules survives the apply_permission_mode transform so the log shows what was unmatched even after Ask→Allow.
    // custom_reason overrides the generic per-verdict reason (used by synthetic Ask sites: parse failure, missing file_path).
PermissionMode  = Default | Plan | AcceptEdits | Auto | DontAsk | BypassPermissions
Filter (trait)  — kind(), data() → Cow<str>, provided to_rule_string() → "Kind(data)"
PathFilter (trait) : Filter — matches(&str), pattern() → &str
Verdict         = Allow | Deny | Ask
RuleSet<F>      { allow: Vec<F>, deny: Vec<F>, ask: Vec<F> }   // push(verdict, F), bucket(verdict) → &[F]
ParsedPermissions  { bash: RuleSet<BashFilter>, read: RuleSet<ReadFilter>, write: RuleSet<WriteFilter>, edit: RuleSet<EditFilter> }
ParsedFilter    = Bash(BashFilter) | Read(ReadFilter) | Write(WriteFilter) | Edit(EditFilter)
BashFilter      { prefix_tokens: Vec<String>, wildcard: bool } ; matches(&[String]) -> bool
{Read,Write,Edit}Filter(String) — PathFilter; ::new(p) debug-asserts p is canonical
FileAccess       { path: String, kind: AccessKind }   // AccessKind = Read | Write
HookInput        { session_id, cwd, tool_name, tool_input, permission_mode? }
ToolInput        { command?, file_path?, path? }          // each tool uses a different subset
HookOutput       { hookEventName, permissionDecision, permissionDecisionReason }
LoadedSettings   { permissions: Permissions, additional_directories: Vec<String> }
VerdictFilter    { show_allow, show_ask, show_deny }  // log output filtering
PythonAnalysis   = Analyzed { accesses } | Unanalyzable(reason)  // python -c analysis result
CommandFileAccesses { reads, writes, inline_script_start, file_only: Option<bool>, effective_cmd_name: Option<String> }
    // file_only: Some(true) = file-only, Some(false) = has network side effects, None = use is_file_only_command()
    // effective_cmd_name: set by wrapper parsers (e.g. uv run) to the inner command's normalized name
```

## Decision flow

```
stdin JSON → parse permission_mode (PermissionMode::from_hook_str) →
  if permission_mode == acceptEdits:
    [BEGINNING STAGE] inject Write/Edit allow rules for workspace dirs
    (CLAUDE_PROJECT_DIR + additionalDirectories) via permission::load_perms
  match tool_name:
  "Bash" | "Monitor" → parse command (thaum) → walk AST:
    for each command:
      0. normalize command name (basename, strip .exe)
      1. check deny Bash rules  →  hit? → Deny
      2. check allow Bash rules →  miss? → collect as unmatched
      3. extract file accesses (redirects + well-known command semantics)
         if uv run: strip wrapper flags, dispatch to inner command's parser
      3b. if python/python3 -c (or effective_cmd_name is python) with static script text:
          parse Python AST → extract file accesses from open() calls and os.* file mutations
          success? → add accesses to file-access list, skip Bash rule
          failure (unsafe patterns, parse error)? → fall back to Bash(python3 -c *)
      3c. if git: parse subcommand → emit Write(.git) for local ops, file_only per category
      4. check deny file rules  →  hit? → Deny
      5. check allow file rules →  miss? → collect as unmatched
      6. decide if Bash rule needed:
         file_only=Some(true) + static args + not bash_asked? → skip Bash rule
         file_only=Some(false)? → require Bash rule
         file_only=None? → use is_file_only_command() + has_file_accesses guard
      ★ suppression: if a `Bash(...)` allow rule matched in step 2, every
         `unmatched` push from steps 3b, 3c, 5, and 6 is skipped (as are the
         eval and parse-failure asks). Step 4's file Deny rules still fire.
    any deny? → Deny
    any unmatched? → Ask (+ populate missing_rules, preserve custom_reason)
    all matched → Allow
  "Grep" | "Glob" → extract path (default cwd) → check against Read rules
  "Read"          → extract file_path → check against Read rules
  "Write" | "Edit"→ extract file_path → check against Write/Edit rules
  other           → silent exit (code 0, regardless of mode)

  [END STAGE] apply_permission_mode(result, mode):
    Ask   → Allow  in auto / bypassPermissions
    Ask   → Deny   in dontAsk (reason lists missing rules)
    Deny  passes through in every mode (authoritative)
    Allow passes through in every mode
```

## Conventions

- Unit tests live inside each module (`#[cfg(test)] mod tests`), not in separate files.
- Integration tests call the library API directly; only binary I/O tests spawn the compiled binary.
- `pretty_assertions` is used in dev for readable test diffs.
- No CI/CD configured yet.
- Conservative defaults: `eval`, dynamic command names, dynamic file paths, and parse failures all result in `ask` under `default` / `plan` / `acceptEdits` **unless a matching `Bash(...)` allow rule suppresses** (see the next bullet). Under `auto` / `bypassPermissions` the end-stage transform converts any remaining Ask to `allow`; under `dontAsk` it converts to `deny` with a reason listing the missing rules.
- **Bash allow suppresses secondary rule demands.** A matching `Bash(...)` **allow** rule suppresses every secondary demand the command would otherwise generate: parser-emitted file accesses (Read/Write), redirect-derived file accesses, parse-failure asks, the `eval` cannot-analyze ask, and the dynamic-command-name ask (via `Bash(*)` / `Bash(**)`). Parser-specific guardrails such as `git -c key=value` and `git config` writes to code-executing keys are also suppressed — a user writing `Bash(git *)` has deliberately accepted all git behavior including `-c core.hooksPath=...`. Authoritative signals that **still** fire: file `Deny(...)` (Read/Write/Edit), Bash `Deny(...)`, and `Ask(Bash(...))` — the latter forces `bash_allowed=false` so the full secondary-demand flow runs.
- `custom_reason` preservation: parse failure and missing-file-path paths set `CheckResult::custom_reason` with a specific error message (e.g. `"Shell command could not be parsed"`). That text survives `apply_permission_mode` and is shown to the user regardless of final verdict — in `Allow` it replaces the generic allow message, in `Deny` under dontAsk it's prefixed onto the deny reason. Normal rule-miss Asks don't set `custom_reason` and fall back to the generic "Missing permission rules: …" text.
- The Edit and Write tools are checked identically (`AccessKind::Write`): `Write(pat)` allows both, `Edit(pat)` also allows both (fallback). There is no way to allow Edit-only while denying Write on the same path.
- Pattern/program arguments in `awk`, `grep`, `rg`, `sed` are skipped during file-access analysis.
- **Permission modes** (`PermissionMode` enum, wire format camelCase): handling lives at two pipeline edges only:
  - **Beginning** (synthetic rule injection, via `permission::load_perms`): `acceptEdits` injects `Write`/`Edit` allow rules for workspace directories.
  - **End** (verdict transform, via `checker::apply_permission_mode`): `auto` and `bypassPermissions` convert `Ask → Allow`; `dontAsk` converts `Ask → Deny` with a reason naming the missing rules; `Allow` and `Deny` pass through unchanged in every mode.
  - The middle layer (parse → extract accesses → match rules) is mode-agnostic. Do not normalize the two-stage split without understanding the tradeoffs.
  - `bypassPermissions` still checks deny rules — a `Deny(Bash(rm *))` rule blocks the command even in bypass mode, matching Claude Code's own documented behavior for hook-deny in bypass. The pre-2026-04 behavior (unconditional allow in bypass) is gone.
  - Unknown tools and empty/unparseable Bash commands continue to silent-exit (`process::exit(0)` with no stdout) in every mode — scriptcheck does not interfere with inputs it wasn't designed to handle. Claude Code applies its own per-mode default for silent-exit cases.
  - `dontAsk` is intended for CI pipelines and non-interactive sessions where prompting is not viable.
  - The `cli::check` subcommand accepts `--permission-mode <mode>` to simulate any mode offline; invalid mode strings are rejected by clap's `ValueEnum`.
- Workspace directories for `acceptEdits` are determined from `CLAUDE_PROJECT_DIR` + `permissions.additionalDirectories` in settings files (matching the official JSON schema at `https://json.schemastore.org/claude-code-settings.json`). A top-level `additionalDirectories` outside `permissions` is ignored. Directories added via `--add-dir` or `/add-dir` at runtime are not visible to the hook.
- Git subcommands are parsed with limited coverage. Read-only subcommands (status, log, diff, show, etc.) are auto-allowed with no rules. Local-write subcommands (add, commit, restore, checkout, merge, etc.) emit `Write(.git)` and are file_only=true — only a Write rule is needed, not a Bash rule. Network subcommands (fetch, pull, push, clone) emit file accesses but are file_only=false — a Bash rule is required unless already covered by a `Bash(...)` allow rule. Unknown subcommands (bisect, submodule, format-patch, archive, subrepo) similarly require a Bash rule unless covered by a `Bash(...)` allow rule. Global options `-C`, `--git-dir`, `--work-tree` are parsed; `-c key=value` is consumed correctly and forces a Bash rule (it can register aliases that intercept any subcommand) — this guardrail is suppressed by a matching `Bash(...)` allow rule, so users writing `Bash(git *)` accept the risk that `git -c core.hooksPath=/evil …` will Allow.
- `git worktree list` is auto-allowed; `add`/`remove`/`move` emit `Write(<path>)` + `Write(.git)` and are file_only=true (for `add <path> <commit-ish>`, only the first positional is treated as a path — the second is a commit-ish); `lock`/`unlock`/`repair`/`prune` emit `Write(.git)`. Unknown `worktree` sub-subcommands require a Bash rule (unless a `Bash(...)` allow rule already covers). `git worktree --help` and `git worktree <sub> --help` (with `--help` as the first arg after the sub-subcommand) are auto-allowed as read-only; later-position `--help`/`-h` is NOT short-circuited because it may be a value for a value-taking flag like `--reason`. An unknown flag in `worktree add` falls through to a Bash rule (an unrecognized value-taking flag could otherwise silently steal the path positional) — again, suppressible by a `Bash(...)` allow rule.
- `git config` reads (`--get`/`--get-all`/`--get-regexp`/`--get-urlmatch`/`--get-color`/`--get-colorbool`/`--list`, `-l`, and bare `git config <key>`) are auto-allowed. Reads with value-pattern positionals like `--get foo.bar pattern` or `--get-urlmatch http https://x` are still reads (2+ positionals don't make them writes). `--file <path>` / `-f <path>` is recorded as a file access and then emitted as either Read or Write depending on the inferred action: for reads, `Read(<path>)` is emitted; for writes, BOTH `Read(<path>)` and `Write(<path>)` are emitted (git parses the file to modify it), so either `Deny(Read(<path>))` or `Deny(Write(<path>))` fires. `--blob <ref>` / `--blob=<ref>` is not a filesystem path and emits no file access. Writes (`--unset`/`--unset-all`/`--add`/`--replace-all`/`--rename-section`/`--remove-section`/`-e`/`--edit`, 2-positional key+value form, and the git ≥ 2.46 subcommand forms `set`/`set-all`/`unset`/`unset-all`/`add`/`replace-all`/`rename-section`/`remove-section`/`edit`) require a Bash rule because config keys like `core.hooksPath`, `core.pager`, `alias.*`, `diff.external`, and `credential.helper` can register arbitrary code execution on subsequent git commands. This guardrail is suppressed by a matching `Bash(...)` allow rule — users writing `Bash(git config *)` or broader accept this tradeoff; `Deny(Write(<path>))` rules against `--file` targets still fire regardless. The subcommand-form `edit` is detected in any positional (not just `args[0]`), so `git config --global edit` or `git config --file <path> edit` are correctly classified as writes. The git ≥ 2.46 `config get`/`list`/`get-regexp`/etc. subcommand forms are intentionally not recognized as reads — they're parsed as positionals via the flag-form scanner to avoid a semantic inversion on older git (where `config get foo.bar` is a setter).
- `git symbolic-ref <name>` reads are auto-allowed; setting (2 positionals) or deleting (`-d`/`--delete`) a ref emits `Write(.git)`. `-m <reason>` is value-taking and doesn't count as a positional.
- Informational invocations (`git` alone, `git --version`, `--help`, bare `--exec-path`/`--html-path`/`--man-path`/`--info-path`) are auto-allowed as read-only. `--help` is only recognized at the global level; `git <subcmd> --help` is not generally detected except for `git worktree [sub] --help`. The `--exec-path=<path>` form (with value) is a setter and falls through to the subcommand.
- Command names are normalized before parser dispatch and rule matching: `/usr/bin/python3` → `python3`, `python.exe` → `python`, `bash.exe` → `bash`. This means `Bash(python3 *)` rules match absolute-path invocations. Versioned Python interpreters (`python3.12`, `python3.13t`) are also recognized.
- `uv run` is a transparent wrapper: `uv run python -c "..."` is analyzed as if `python -c "..."` were the command. The wrapper's flags (`--with`, `--directory`, etc.) are consumed; unrecognized flags force a Bash rule (unless a matching `Bash(uv run *)` allow rule already covers). The logged rule is `Bash(uv run python -c *)`, matching the actual command.
- The `Monitor` tool is treated as a transparent wrapper around `Bash`: its `command` field is parsed and analyzed identically, and the same `Bash(...)` allow/deny rules apply. The `description`, `persistent`, and `timeout_ms` fields are ignored — they affect runtime lifetime and presentation, not what the command does. So `Monitor("tail -f /tmp/x")` is auto-allowed under `Bash(tail -f *)` exactly like a direct Bash call. Monitor is logged identically to Bash in every mode (the prior `Monitor(bypassPermissions)` special-case log label is gone with the end-stage transform).
- `python -c` and `python3 -c` inline scripts are analyzed via Python AST (rustpython-parser). If the script only uses `open()` with static string paths and no unsafe patterns (exec, eval, subprocess, shutil, etc.), file accesses are extracted and checked against Read/Write rules — no `Bash()` rule is needed. Unanalyzable scripts fall back to `Bash(python3 -c *)`.
- Python AST analysis covers: `open()` and `io.open()` for file reads/writes; `os.remove`/`os.unlink`/`os.rmdir`/`os.removedirs`/`os.makedirs`/`os.mkdir`/`os.truncate`/`os.chmod`/`os.chown` etc. as Write(path); `os.rename`/`os.replace`/`os.link`/`os.symlink` as Read(src)+Write(dst). All require static string paths; dynamic paths fall back to Ask. `shutil.*` still triggers fallback. `pathlib.Path` method chains are not yet detected.
- `rustpython-parser` 0.4.0 does not support Python 3.12 relaxed f-string quoting (PEP 701). Scripts with `f"{d["key"]}"` (same quote type inside and outside f-string braces) fail to parse. The workaround is to use different quote types: `f'{d["key"]}'`.
- Backticks in Python comments inside double-quoted `-c` scripts (e.g. `` python -c "# see `code` here" ``) cause thaum to see command substitution, making the word dynamic and the script unanalyzable. This is a bash semantics issue, not a parser bug. Use single-quoted scripts to avoid.
- On Windows, managed settings are loaded from `%ProgramData%\ClaudeCode\managed-settings.json`.
- `CLAUDE_SCRIPTCHECK_HOOK_HOME=<path>` overrides the home directory used by the hook dispatch path (settings loading + tilde expansion in rules and file-access paths). It does **not** affect `claude-scriptcheck install`/`uninstall`/`upgrade`, which always target the real `~/.claude/`. Primarily intended for test isolation — needed on Windows because `dirs::home_dir()` there calls `SHGetKnownFolderPath(FOLDERID_Profile)` and ignores `HOME`/`USERPROFILE`/`HOMEDRIVE`+`HOMEPATH`. It is a supported env var; setting it in a user shell will take effect. Empty/whitespace-only values are treated as unset.
- `CLAUDE_SCRIPTCHECK_LOG_PATH=<path>` overrides the log file location for both writers (`log_decision`) and readers (`cli::log`, `cli::log-path`). Primarily intended for test isolation but supported generally. Empty/whitespace-only values are treated as unset.
