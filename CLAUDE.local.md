# Local workflow

## Issue tracking

When an issue is discovered, create a GitHub issue to track the work before starting implementation.

## Branching

All changes go in a separate git worktree, on a branch named `azhukova/<ISSUE-NUMBER>`, where `<ISSUE-NUMBER>` is the GitHub issue number for the work. Do not push directly to `main` or make implementation changes in the root worktree.

## Plans must include

- Working from the issue-linked worktree branch, not `main`.
- Opening a PR against `main`.
- Verifying that CI passes on the PR before merge.
