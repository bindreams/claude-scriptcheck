# Dual-Agent Hook Design

Date: 2026-06-17
Project: `claude-scriptcheck`
Status: Approved design, awaiting user review before implementation planning

## Summary

`claude-scriptcheck` will support both Claude and Codex through an explicit agent adapter layer. The command-evaluation and permission-checking logic remains shared and agent-agnostic. Agent-specific behavior is isolated to hook I/O, config loading, and install or uninstall wiring.

The runtime will use an explicit `--agent` flag only. Autodetection is out of scope for this design. Claude and Codex will each load their own native configuration and rules. Codex support will use `PreToolUse` only for now. Codex `PermissionRequest` will not be integrated in this iteration.

## Goals

- Preserve the current command and file-access evaluation substance.
- Support both Claude and Codex cleanly from one binary.
- Make agent selection explicit and deterministic.
- Keep agent-specific I/O and config behavior out of the shared checker.
- Add install and uninstall support for both agents.
- Implement the work via TDD so behavior remains stable during refactoring.

## Non-Goals

- No autodetection of the calling agent.
- No Codex `PermissionRequest` integration in this iteration.
- No semantic change to the existing permission engine beyond adapter-driven mapping.
- No speculative support for additional agents in this iteration, though the design should make that straightforward later.

## Confirmed External Behavior

The relevant behavior established for this design is:

- Claude has a native hook contract that supports `allow`, `deny`, and `ask`.
- Codex does not have a supported Claude-style `ask` result for `PreToolUse`.
- Codex can decline to decide and fall back to its native approval flow.
- Empirical testing on 2026-06-17 verified that Codex invokes `PreToolUse` before `PermissionRequest` for the same tool call.

This design intentionally does not depend on Codex `PermissionRequest`, because there is no approved second-stage policy behavior that requires it.

## Architecture

The implementation will be split into three layers.

### Core policy engine

The shared engine remains responsible for:

- parsing and analyzing commands
- extracting file accesses
- loading and applying permission rules once a normalized rule source is provided
- returning a core decision result

The core result model remains conceptually:

- `Allow`
- `Deny`
- `Ask`

It also carries the existing matched rules, missing rules, and reason text.

The engine must not know whether it is serving Claude or Codex. It must not encode hook JSON formats, config file locations, or install rules.

### Agent adapters

Each supported agent will have its own adapter responsible for:

- parsing hook input from that agent
- normalizing the incoming request into the shared internal request model
- mapping the shared decision result back into that agent’s hook output format
- loading that agent’s configuration and permission rules
- installing and uninstalling that agent’s native hook entries

This design requires two adapters:

- Claude adapter
- Codex adapter

### CLI and entrypoint layer

The binary remains `claude-scriptcheck`, but hook execution will require an explicit agent selector:

- `claude-scriptcheck --agent claude`
- `claude-scriptcheck --agent codex`

Non-hook commands that operate on configuration, especially install and uninstall, will also require explicit agent selection.

## Agent Semantics

### Claude

Claude preserves current behavior. The Claude adapter will continue mapping the shared engine result to Claude’s native hook semantics:

- `Allow -> allow`
- `Deny -> deny`
- `Ask -> ask`

Claude configuration loading continues to read Claude settings and permission rules.

### Codex

Codex support uses `PreToolUse` only in this iteration.

The Codex adapter maps the shared engine result as follows:

- `Deny -> deny`
- `Ask -> no verdict`
- `Allow -> allow`

Returning no verdict means `claude-scriptcheck` declines to decide and Codex continues with its native behavior for unresolved cases. Returning `allow` means `claude-scriptcheck` is explicitly taking over approval for cases the shared engine fully permits.

The Codex adapter does not use `PermissionRequest` in this design.

## Configuration Loading

Configuration discovery is agent-specific.

- The Claude adapter loads Claude configuration and Claude permission rules.
- The Codex adapter loads Codex configuration and Codex permission rules.

The shared checker receives normalized permission data only. Shared modules must not contain logic that says “if Claude” or “if Codex” when deciding where to read configuration from.

The code should make the rule source an explicit adapter concern, not an ambient global assumption.

## Install And Uninstall Surface

The install-family commands will be agent-selecting subcommands:

- `claude-scriptcheck install claude`
- `claude-scriptcheck install codex`
- `claude-scriptcheck uninstall claude`
- `claude-scriptcheck uninstall codex`

Installation behavior:

- Claude installation edits Claude configuration and writes hook commands that invoke `claude-scriptcheck --agent claude`.
- Codex installation edits Codex configuration and writes `PreToolUse` hook entries that invoke `claude-scriptcheck --agent codex`.

Uninstall behavior removes only the entries owned by the selected agent path.

This design intentionally avoids shared “best guess” installation logic. The selected agent is the sole authority for install target and hook command shape.

## Internal Boundaries

The refactor target is to stop treating Claude’s hook payload structures as the application model.

Instead:

- shared internal request and response types become the application model
- Claude hook structs become Claude transport types
- Codex hook structs become Codex transport types

The existing Claude-specific hook and settings code should be moved behind the Claude adapter rather than remaining in generic top-level modules.

## Testing Strategy

The implementation will follow TDD in three slices.

### 1. Core-preservation tests

Add or retain tests that prove the checker behavior is unchanged while extracting adapter boundaries. These tests protect command analysis, file-access extraction, permission matching, and mode handling from accidental semantic drift.

### 2. Adapter tests

Add tests for:

- Claude hook input and output behavior preserving current semantics
- Codex `PreToolUse` input parsing and output mapping
- Codex `Ask -> no verdict`
- Codex `Allow -> allow`
- Claude configuration loading using Claude config sources
- Codex configuration loading using Codex config sources
- Claude install and uninstall writing the Claude command line
- Codex install and uninstall writing the Codex command line

### 3. CLI tests

Add tests for:

- explicit `--agent` requirement in hook mode
- install and uninstall agent selection behavior
- invalid CLI combinations failing clearly

## Migration Strategy

Implementation should be incremental rather than a rewrite.

Recommended order:

1. Introduce shared internal request and response types plus an explicit agent enum.
2. Move current Claude hook behavior behind a Claude adapter without changing Claude semantics.
3. Add Codex transport and configuration support through a Codex adapter.
4. Refactor install and uninstall code to dispatch through agent-specific installers.
5. Tighten CLI parsing around explicit agent selection.

At each step, tests should prove that the existing Claude path still behaves the same unless the test intentionally covers new agent behavior.

## Open Design Constraints For Implementation

These decisions are fixed for implementation:

- explicit `--agent` only
- no autodetection
- Codex uses `PreToolUse` only
- Codex `Ask -> no verdict`
- Codex `Allow -> allow`
- Claude preserves current semantics

Implementation may still choose the exact module layout and type names as long as those choices preserve the boundaries defined in this document.
