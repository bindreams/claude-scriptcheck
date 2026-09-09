# claude-scriptcheck

AST-aware Bash permission checker for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and Codex hooks.

Instead of relying on simple prefix matching, claude-scriptcheck **parses** every
Bash command into an AST (using [thaum](https://github.com/bindreams/thaum)), walks it,
and checks two things for each statement:

1. **Command identity** — is this command allowed by a `Bash(...)` rule in your settings?
1. **File access** — does the command read or write files (via redirects *or*
   well-known command semantics), and are those paths covered by `Read(...)` /
   `Write(...)` / `Edit(...)` rules?

If everything is covered: **allow**.
If any rule explicitly denies: **deny**.
Otherwise: **ask** the user, and log the missing rules for later review.

## Quick start

```sh
# Install from GitHub (requires Rust toolchain)
cargo install --git https://github.com/bindreams/claude-scriptcheck.git

# Register the hook in Claude settings
claude-scriptcheck install claude

# Register the hook in Codex config.toml
claude-scriptcheck install codex

# Hook mode is explicit
claude-scriptcheck --agent claude
claude-scriptcheck --agent codex
```

To update later, run the same `cargo install` command again. To remove:

```sh
claude-scriptcheck uninstall claude
claude-scriptcheck uninstall codex
cargo uninstall claude-scriptcheck
```

## Development

Local linting and formatting are driven by `prek.toml` so the same checks run
both on a developer machine and in CI:

```sh
uv tool install "prek==0.3.6"
cargo install --locked taplo-cli --version 0.10.0
prek install

# Preferred when your local hook setup allows it
prek run --all-files

# If a local pre-tool hook blocks `--all-files`, stage the files and lint the
# staged set instead
git add .
prek run

cargo test --locked
```

Pull requests are expected to go green in `.github/workflows/ci.yaml` before
landing in `main`.

## How it works

claude-scriptcheck registers itself as a pre-tool hook for each supported agent.
Claude uses the existing `Bash`, `Monitor`, `Read`, `Write`, `Edit`, `Grep`, and
`Glob` tool surface. Codex currently uses `PreToolUse` for `Bash` and
`apply_patch`.

```
┌─────────────┐  JSON stdin    ┌─────────────────────┐  JSON stdout   ┌─────────────┐
│ Claude Code ├───────────────►│ claude-scriptcheck  ├───────────────►│ Claude Code │
│             │  tool_name,    │                     │  allow / deny  │             │
│             │  tool_input    │ 1. parse with thaum │  / ask         │             │
└─────────────┘                │ 2. walk AST         │                └─────────────┘
                               │ 3. check rules      │
                               │ 4. decide           │
                               └─────────────────────┘
```

### Decision logic

For each simple command in the parsed AST:

| Check                    | Source                                                 | Rule format                  |
| ------------------------ | ------------------------------------------------------ | ---------------------------- |
| Is this command allowed? | `Bash(cmd)`, `Bash(cmd *)`                             | Prefix match, `*` = any args |
| Does it read files?      | `<` redirects, `cat`, `head`, `source`, ...            | `Read(glob)`                 |
| Does it write files?     | `>`, `>>`, `&>` redirects, `cp` dest, `rm`, `tee`, ... | `Write(glob)`, `Edit(glob)`  |

- **All checks pass** → `allow` (auto-approved, no prompt)
- **Any deny rule matches** → `deny` (blocked)
- **Some rules missing** → `ask` (user prompted) + missing rules logged

### What gets walked

The checker recurses through the full AST:

- Pipelines (`cmd1 | cmd2`)
- Logical chains (`cmd1 && cmd2`, `cmd1 || cmd2`)
- Compound commands (`if`/`for`/`while`/`case`/`{}`/`()`)
- Function definitions
- Process substitutions (`<(cmd)`, `>(cmd)`)
- Command substitutions (`$(cmd)`, `` `cmd` ``)
- All I/O redirections (`>`, `>>`, `<`, `&>`, `<>`, etc.)

### Conservative cases

| Scenario                          | Decision                                             |
| --------------------------------- | ---------------------------------------------------- |
| `eval ...`                        | Always `ask` — cannot be statically analyzed         |
| Dynamic command name (`$CMD arg`) | `ask`                                                |
| Dynamic file path (`cat $FILE`)   | Skip file check; approve if `Bash(cat *)` is allowed |
| Parse failure                     | `ask`                                                |
| `/dev/null`, `/dev/stdin`, etc.   | Ignored (no file rule needed)                        |

## CLI reference

Hook mode always requires an explicit top-level agent flag:

```sh
claude-scriptcheck --agent claude
claude-scriptcheck --agent codex
```

Management and dry-run commands use a positional agent selector:

### `install` / `uninstall`

```sh
# Install to global Claude settings (~/.claude/settings.json)
claude-scriptcheck install claude

# Install to global Codex settings (~/.codex/config.toml or $CODEX_HOME/config.toml)
claude-scriptcheck install codex

# Install to project-level settings
claude-scriptcheck install claude --project
claude-scriptcheck install codex --project

# Remove hooks
claude-scriptcheck uninstall claude
claude-scriptcheck uninstall codex
```

### `check`

Manually test a command against the selected agent's current rules:

```sh
claude-scriptcheck check claude "ls -la /tmp"
# ALLOW: All commands and file accesses are permitted

claude-scriptcheck check codex "rm -rf /"
# ASK: Missing permission rules:
#   - Bash(rm -rf /)
#   - Write(/)

claude-scriptcheck check claude "echo hello > /tmp/claude/out.txt"
# ALLOW: All commands and file accesses are permitted

claude-scriptcheck check codex --cwd /some/project "cat src/main.rs"
# (checks against /some/project's settings too)
```

### `log` / `log-path`

Commands that result in an `ask` decision are logged with the missing rules:

```sh
# Print the log
claude-scriptcheck log

# Print and clear
claude-scriptcheck log --clear

# Show where the log lives
claude-scriptcheck log-path
# ~/.local/state/claude-scriptcheck/missing-rules.log  (Linux)
# ~/Library/Logs/claude-scriptcheck/missing-rules.log   (macOS)
```

The log is useful for discovering which rules you're missing and adding them
to your settings.

## Settings format

Claude rules are read from `~/.claude/settings.json` (global) and
`.claude/settings.json` (project-level), merging both:

```jsonc
{
  "permissions": {
    "allow": [
      // Command rules
      "Bash(ls)",           // exact: only bare `ls`
      "Bash(ls *)",         // with wildcard: `ls` with any arguments
      "Bash(git status *)", // multi-token prefix

      // File access rules (glob patterns, ~ expanded)
      "Read(~/src/**)",
      "Write(/tmp/claude/**)",
      "Edit(/tmp/claude/**)"
    ],
    "deny": [
      "Bash(rm -rf /)",
      "Read(/etc/shadow)"
    ]
  }
}
```

Codex rules live in `config.toml` under `[scriptcheck.permissions]`:

```toml
[scriptcheck.permissions]
allow = ["Bash(ls *)", "Write(/tmp/claude/**)"]
deny = ["Bash(rm -rf /)"]
ask = ["Bash(curl *)"]
```

Codex hook installation writes inline `[[hooks.PreToolUse]]` entries into the
target `config.toml`. It refuses to modify that layer if a sibling `hooks.json`
already exists, so one Codex layer has exactly one hook representation.

## Well-known commands

claude-scriptcheck understands the file-access semantics of common commands:

| Category                   | Commands                                                                                                                                                                                                                               |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Read** (non-flag args)   | `cat`, `head`, `tail`, `less`, `more`, `wc`, `file`, `stat`, `md5sum`, `shasum`, `sha256sum`, `xxd`, `hexdump`, `diff`, `grep`, `rg`, `find`, `sort`, `uniq`, `cut`, `awk`, `tr`, `strings`, `readelf`, `objdump`, `nm`, `ldd`, `size` |
| **Read src + Write dst**   | `cp`, `mv`, `install`, `ln`                                                                                                                                                                                                            |
| **Write** (non-flag args)  | `rm`, `rmdir`, `mkdir`, `touch`, `tee`                                                                                                                                                                                                 |
| **Write** (skip first arg) | `chmod`, `chown`, `chgrp`                                                                                                                                                                                                              |
| **Read first arg**         | `source`, `.`                                                                                                                                                                                                                          |
| **Write if `-i`**          | `sed`                                                                                                                                                                                                                                  |
| **No file access**         | `echo`, `printf`, `pwd`, `env`, `date`, `cd`, builtins, ...                                                                                                                                                                            |

Commands not in the table produce no file-access entries (the `Bash(...)` rule
check still applies).
