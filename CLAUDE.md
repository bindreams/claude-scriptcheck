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
| `src/settings.rs`    | Loads and merges permission rules + `additionalDirectories` (both nested inside `permissions` and top-level) from settings files. Returns `LoadedSettings`. |
| `src/logging.rs`     | Appends decisions to platform-specific log file. Read-back helpers: `split_documents()`, `extract_verdict()`.       |
| `src/path_util.rs`   | Cross-platform path helpers: `is_absolute()`, `normalize_separators()`.                                            |
| `src/python_ast.rs`  | Python AST analysis for `python -c` inline scripts. Parses Python, extracts file accesses, detects unsafe patterns.|
| `src/cmd_parser/git.rs` | Git subcommand parser. Dispatches on subcommand, emits Write(.git) for local ops, file_only=false for network ops.|
| `src/cmd_parser/wrappers.rs` | Wrapper command parsers (e.g. `uv run`). Strips wrapper flags, dispatches to inner command's parser.         |
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
CommandFileAccesses { reads, writes, inline_script_start, file_only: Option<bool>, effective_cmd_name: Option<String> }
    // file_only: Some(true) = file-only, Some(false) = has network side effects, None = use is_file_only_command()
    // effective_cmd_name: set by wrapper parsers (e.g. uv run) to the inner command's normalized name
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
- Workspace directories for `acceptEdits` are determined from `CLAUDE_PROJECT_DIR` + `permissions.additionalDirectories` in settings files (matching the official JSON schema at `https://json.schemastore.org/claude-code-settings.json`). A top-level `additionalDirectories` outside `permissions` is ignored. Directories added via `--add-dir` or `/add-dir` at runtime are not visible to the hook.
- Git subcommands are parsed with limited coverage. Read-only subcommands (status, log, diff, show, etc.) are auto-allowed with no rules. Local-write subcommands (add, commit, restore, checkout, merge, etc.) emit `Write(.git)` and are file_only=true — only a Write rule is needed, not a Bash rule. Network subcommands (fetch, pull, push, clone) emit file accesses but are file_only=false — a Bash rule is always required. Unknown subcommands (bisect, submodule, format-patch, archive, subrepo) require a Bash rule. Global options `-C`, `--git-dir`, `--work-tree` are parsed; `-c key=value` is consumed correctly and always forces a Bash rule (it can register aliases that intercept any subcommand).
- `git worktree list` is auto-allowed; `add`/`remove`/`move` emit `Write(<path>)` + `Write(.git)` and are file_only=true (for `add <path> <commit-ish>`, only the first positional is treated as a path — the second is a commit-ish); `lock`/`unlock`/`repair`/`prune` emit `Write(.git)`. Unknown `worktree` sub-subcommands require a Bash rule. `git worktree --help` and `git worktree <sub> --help` (with `--help` as the first arg after the sub-subcommand) are auto-allowed as read-only; later-position `--help`/`-h` is NOT short-circuited because it may be a value for a value-taking flag like `--reason`. An unknown flag in `worktree add` falls through to a Bash rule (an unrecognized value-taking flag could otherwise silently steal the path positional).
- `git config` reads (`--get`/`--get-all`/`--get-regexp`/`--get-urlmatch`/`--get-color`/`--get-colorbool`/`--list`, `-l`, and bare `git config <key>`) are auto-allowed. Reads with value-pattern positionals like `--get foo.bar pattern` or `--get-urlmatch http https://x` are still reads (2+ positionals don't make them writes). `--file <path>` / `-f <path>` is recorded as a file access and then emitted as either Read or Write depending on the inferred action: for reads, `Read(<path>)` is emitted; for writes, BOTH `Read(<path>)` and `Write(<path>)` are emitted (git parses the file to modify it), so either `Deny(Read(<path>))` or `Deny(Write(<path>))` fires. `--blob <ref>` / `--blob=<ref>` is not a filesystem path and emits no file access. Writes (`--unset`/`--unset-all`/`--add`/`--replace-all`/`--rename-section`/`--remove-section`/`-e`/`--edit`, 2-positional key+value form, and the git ≥ 2.46 subcommand forms `set`/`set-all`/`unset`/`unset-all`/`add`/`replace-all`/`rename-section`/`remove-section`/`edit`) still require a Bash rule because config keys like `core.hooksPath`, `core.pager`, `alias.*`, `diff.external`, and `credential.helper` can register arbitrary code execution on subsequent git commands. The subcommand-form `edit` is detected in any positional (not just `args[0]`), so `git config --global edit` or `git config --file <path> edit` are correctly classified as writes. The git ≥ 2.46 `config get`/`list`/`get-regexp`/etc. subcommand forms are intentionally not recognized as reads — they're parsed as positionals via the flag-form scanner to avoid a semantic inversion on older git (where `config get foo.bar` is a setter).
- `git symbolic-ref <name>` reads are auto-allowed; setting (2 positionals) or deleting (`-d`/`--delete`) a ref emits `Write(.git)`. `-m <reason>` is value-taking and doesn't count as a positional.
- Informational invocations (`git` alone, `git --version`, `--help`, bare `--exec-path`/`--html-path`/`--man-path`/`--info-path`) are auto-allowed as read-only. `--help` is only recognized at the global level; `git <subcmd> --help` is not generally detected except for `git worktree [sub] --help`. The `--exec-path=<path>` form (with value) is a setter and falls through to the subcommand.
- Command names are normalized before parser dispatch and rule matching: `/usr/bin/python3` → `python3`, `python.exe` → `python`, `bash.exe` → `bash`. This means `Bash(python3 *)` rules match absolute-path invocations. Versioned Python interpreters (`python3.12`, `python3.13t`) are also recognized.
- `uv run` is a transparent wrapper: `uv run python -c "..."` is analyzed as if `python -c "..."` were the command. The wrapper's flags (`--with`, `--directory`, etc.) are consumed; unrecognized flags force a Bash rule. The logged rule is `Bash(uv run python -c *)`, matching the actual command.
- `python -c` and `python3 -c` inline scripts are analyzed via Python AST (rustpython-parser). If the script only uses `open()` with static string paths and no unsafe patterns (exec, eval, subprocess, shutil, etc.), file accesses are extracted and checked against Read/Write rules — no `Bash()` rule is needed. Unanalyzable scripts fall back to `Bash(python3 -c *)`.
- Python AST analysis covers: `open()` and `io.open()` for file reads/writes; `os.remove`/`os.unlink`/`os.rmdir`/`os.removedirs`/`os.makedirs`/`os.mkdir`/`os.truncate`/`os.chmod`/`os.chown` etc. as Write(path); `os.rename`/`os.replace`/`os.link`/`os.symlink` as Read(src)+Write(dst). All require static string paths; dynamic paths fall back to Ask. `shutil.*` still triggers fallback. `pathlib.Path` method chains are not yet detected.
- `rustpython-parser` 0.4.0 does not support Python 3.12 relaxed f-string quoting (PEP 701). Scripts with `f"{d["key"]}"` (same quote type inside and outside f-string braces) fail to parse. The workaround is to use different quote types: `f'{d["key"]}'`.
- Backticks in Python comments inside double-quoted `-c` scripts (e.g. `` python -c "# see `code` here" ``) cause thaum to see command substitution, making the word dynamic and the script unanalyzable. This is a bash semantics issue, not a parser bug. Use single-quoted scripts to avoid.
