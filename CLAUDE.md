# claude-scriptcheck

AST-aware Bash permission checker, used as a Claude Code pre-tool-use hook.
Parses shell commands with [thaum](https://github.com/bindreams/thaum), walks the AST, and decides **allow / deny / ask** based on permission rules in Claude's `settings.json`.

## Build & test

```sh
cargo build              # debug build
cargo build --release    # release build (thin LTO, opt-level 2)
cargo test               # all unit + integration tests
cargo install --git https://github.com/bindreams/claude-scriptcheck.git  # install/upgrade
```

## Source map

| File                   | Role                                                                                                              |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `src/lib.rs`           | Library crate root. Re-exports all modules so they are usable without spawning the binary.                        |
| `src/main.rs`          | Thin binary wrapper: CLI routing (clap) and hook-mode I/O (stdin JSON → decision JSON).                           |
| `src/cli.rs`           | Subcommand implementations: `install`, `uninstall`, `check`, `log`, `log-path`, `upgrade`.                        |
| `src/checker.rs`       | Core logic. `check_program()` walks AST, checks each command against rules, returns `Decision`. ~60 unit tests.   |
| `src/permission.rs`    | Parses rule strings (`Bash(cmd *)`, `Read(glob)`, etc.) into `ParsedPermissions`. Matching logic. ~20 unit tests. |
| `src/file_access.rs`   | Maps well-known commands to file-access semantics (read/write args, redirects). ~25 unit tests.                   |
| `src/hook.rs`          | `HookInput` / `HookOutput` serde structs for JSON protocol with Claude Code.                                      |
| `src/settings.rs`      | Loads and merges permission rules from global + project settings files.                                           |
| `src/logging.rs`       | Appends missing rules to platform-specific log file.                                                              |
| `src/word_util.rs`     | Extracts static string literals from bash `Word` nodes; detects dynamic content.                                  |
| `tests/integration.rs` | Integration tests: logic tests call the library API directly; binary I/O tests invoke the compiled binary.        |

## Key types

```
Decision        = Allow | Deny(reason) | Ask(Vec<missing_rules>)
ParsedPermissions  { allow_bash, deny_bash, allow_read, deny_read, allow_write, deny_write, allow_edit, deny_edit }
BashRule         { prefix_tokens: Vec<String>, wildcard: bool }
FileAccess       { path: String, kind: AccessKind }   // AccessKind = Read | Write
HookInput        { session_id, cwd, tool_name, tool_input }
HookOutput       { hookEventName, permissionDecision, permissionDecisionReason }
```

## Decision flow

```
stdin JSON → is tool_name "Bash"? → parse command (thaum) → walk AST:
  for each command:
    1. check deny Bash rules  →  hit? → Deny
    2. check allow Bash rules →  miss? → collect as unmatched
    3. extract file accesses (redirects + well-known command semantics)
    4. check deny file rules  →  hit? → Deny
    5. check allow file rules →  miss? → collect as unmatched
  any deny? → Deny
  any unmatched? → Ask (+ log missing rules)
  all matched → Allow
```

## Conventions

- Unit tests live inside each module (`#[cfg(test)] mod tests`), not in separate files.
- Integration tests call the library API directly; only binary I/O tests spawn the compiled binary.
- `pretty_assertions` is used in dev for readable test diffs.
- No CI/CD configured yet.
- Conservative defaults: `eval`, dynamic command names, dynamic file paths, and parse failures all result in `ask`.
- `/dev/*` paths are silently ignored (no rule needed).
- Pattern/program arguments in `awk`, `grep`, `rg`, `sed` are skipped during file-access analysis.
