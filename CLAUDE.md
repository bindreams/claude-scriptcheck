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
| `src/main.rs`        | Binary: CLI routing (clap), hook-mode dispatch (Bash/Grep/Glob/Read/Write/Edit), I/O (stdin JSON → decision JSON). |
| `src/cli.rs`         | Subcommand implementations: `install`, `uninstall`, `check`, `log`, `log-path`, `upgrade`. `VerdictFilter` type.   |
| `src/checker.rs`     | Core logic. `check_program()` for Bash AST, `check_file_accesses()` for non-Bash tools. Returns `Decision`.        |
| `src/permission.rs`  | Parses rule strings (`Bash(cmd *)`, `Read(glob)`, etc.) into `ParsedPermissions`. Matching logic. ~20 unit tests.  |
| `src/file_access.rs` | Maps well-known commands to file-access semantics (read/write args, redirects). ~25 unit tests.                    |
| `src/hook.rs`        | `HookInput` / `HookOutput` serde structs for JSON protocol with Claude Code.                                       |
| `src/settings.rs`    | Loads and merges permission rules + `additionalDirectories` from settings files. Returns `LoadedSettings`.         |
| `src/logging.rs`     | Appends decisions to platform-specific log file. Read-back helpers: `split_documents()`, `extract_verdict()`.       |
| `src/path_util.rs`   | Cross-platform path helpers: `is_absolute()`, `normalize_separators()`.                                            |
| `src/word_util.rs`   | Extracts static string literals from bash `Word` nodes; detects dynamic content.                                   |
| `src/python_ast.rs`  | Python AST analysis for `python -c` inline scripts. Parses Python, extracts file accesses, detects unsafe patterns.|
| `src/cmd_parser/git.rs` | Git subcommand parser. Dispatches on subcommand, emits Write(.git) for local ops, file_only=false for network ops.|
| `tests/suite/`       | Integration tests: logic tests call the library API directly; binary I/O tests invoke the compiled binary.         |

## Key types

```
Decision        = Allow | Deny(reason) | Ask(Vec<missing_rules>)
ParsedPermissions  { allow_bash, deny_bash, allow_read, deny_read, allow_write, deny_write, allow_edit, deny_edit }
BashRule         { prefix_tokens: Vec<String>, wildcard: bool }
FileAccess       { path: String, kind: AccessKind }   // AccessKind = Read | Write
HookInput        { session_id, cwd, tool_name, tool_input, permission_mode? }
ToolInput        { command?, file_path?, path? }          // each tool uses a different subset
HookOutput       { hookEventName, permissionDecision, permissionDecisionReason }
LoadedSettings   { permissions: Permissions, additional_directories: Vec<String> }
VerdictFilter    { show_allow, show_ask, show_deny }  // log output filtering
PythonAnalysis   = Analyzed { accesses } | Unanalyzable(reason)  // python -c analysis result
CommandFileAccesses { reads, writes, inline_script_start, file_only: Option<bool> }
    // file_only: Some(true) = file-only, Some(false) = has network side effects, None = use is_file_only_command()
```

## Decision flow

```
stdin JSON → parse permission_mode →
  if permission_mode == "bypassPermissions":
    log + output allow immediately (no further processing)
  if permission_mode == "acceptEdits":
    inject Write/Edit allow rules for workspace dirs (CLAUDE_PROJECT_DIR + additionalDirectories)
  match tool_name:
  "Bash" → parse command (thaum) → walk AST:
    for each command:
      1. check deny Bash rules  →  hit? → Deny
      2. check allow Bash rules →  miss? → collect as unmatched
      3. extract file accesses (redirects + well-known command semantics)
      3b. if python/python3 -c with static script text:
          parse Python AST → extract file accesses from open() calls
          success? → add accesses to file-access list, skip Bash rule
          failure (unsafe patterns, parse error)? → fall back to Bash(python3 -c *)
      3c. if git: parse subcommand → emit Write(.git) for local ops, file_only per category
      4. check deny file rules  →  hit? → Deny
      5. check allow file rules →  miss? → collect as unmatched
      6. decide if Bash rule needed:
         file_only=Some(true) + static args + not bash_asked? → skip Bash rule
         file_only=Some(false)? → require Bash rule
         file_only=None? → use is_file_only_command() + has_file_accesses guard
    any deny? → Deny
    any unmatched? → Ask (+ log missing rules)
    all matched → Allow
  "Grep" | "Glob" → extract path (default cwd) → check against Read rules
  "Read"          → extract file_path → check against Read rules
  "Write" | "Edit"→ extract file_path → check against Write/Edit rules
  other           → silent exit (code 0)
```

## Conventions

- Unit tests live inside each module (`#[cfg(test)] mod tests`), not in separate files.
- Integration tests call the library API directly; only binary I/O tests spawn the compiled binary.
- `pretty_assertions` is used in dev for readable test diffs.
- No CI/CD configured yet.
- Conservative defaults: `eval`, dynamic command names, dynamic file paths, and parse failures all result in `ask`.
- The Edit and Write tools are checked identically (`AccessKind::Write`): `Write(pat)` allows both, `Edit(pat)` also allows both (fallback). There is no way to allow Edit-only while denying Write on the same path.
- Pattern/program arguments in `awk`, `grep`, `rg`, `sed` are skipped during file-access analysis.
- When `permission_mode` is `"bypassPermissions"`, the hook unconditionally allows all tool calls (including unknown tools) without loading settings or running any checks. Decisions are still logged.
- When `permission_mode` is `"acceptEdits"`, ephemeral Write/Edit allow rules are injected for workspace directories. Deny and ask rules still take priority. The `cli::check` subcommand does not support `--permission-mode`.
- Workspace directories for `acceptEdits` are determined from `CLAUDE_PROJECT_DIR` + `additionalDirectories` in settings files. Directories added via `--add-dir` or `/add-dir` at runtime are not visible to the hook.
- Git subcommands are parsed with limited coverage. Read-only subcommands (status, log, diff, show, etc.) are auto-allowed with no rules. Local-write subcommands (add, commit, restore, checkout, merge, etc.) emit `Write(.git)` and are file_only=true — only a Write rule is needed, not a Bash rule. Network subcommands (fetch, pull, push, clone) emit file accesses but are file_only=false — a Bash rule is always required. Unknown subcommands (config, bisect, worktree, submodule, format-patch, archive) require a Bash rule. Global options `-C`, `--git-dir`, `--work-tree` are parsed; `-c key=value` is consumed correctly.
- `python -c` and `python3 -c` inline scripts are analyzed via Python AST (rustpython-parser). If the script only uses `open()` with static string paths and no unsafe patterns (exec, eval, subprocess, os file-mutation, shutil, etc.), file accesses are extracted and checked against Read/Write rules — no `Bash()` rule is needed. Unanalyzable scripts fall back to `Bash(python3 -c *)`. Phase 1 covers `open()` and `io.open()` only; `os.remove`/`os.rename`/etc. and `shutil.*` trigger fallback to Ask. `pathlib.Path` method chains are not yet detected (future Phase 2 work).
