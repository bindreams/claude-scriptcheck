use super::{resolve, CommandFileAccesses, CommandParser};

pub(super) struct GitParser;

/// Context derived from global options, passed to subcommand handlers.
struct GitContext {
    /// Where the .git directory lives (default: `{work_tree}/.git`).
    git_dir: String,
    /// Where the working tree lives (default: effective cwd).
    work_tree: String,
}

impl GitContext {
    fn read_only(&self) -> CommandFileAccesses {
        CommandFileAccesses {
            reads: vec![],
            writes: vec![],
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        }
    }

    fn write_git(&self) -> CommandFileAccesses {
        CommandFileAccesses {
            reads: vec![],
            writes: vec![self.git_dir.clone()],
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        }
    }

    /// Operation that modifies working tree + .git but we can't enumerate
    /// specific file paths (e.g. merge, checkout branch, reset --hard).
    /// Only emits Write(.git) since it's always inside the project directory
    /// and matches `Write(project/**)` patterns.
    fn write_worktree_and_git(&self) -> CommandFileAccesses {
        self.write_git()
    }

    fn network_write_git(&self) -> CommandFileAccesses {
        CommandFileAccesses {
            reads: vec![],
            writes: vec![self.git_dir.clone()],
            inline_script_start: None,
            file_only: Some(false),
            ..Default::default()
        }
    }

    fn network_write_worktree_and_git(&self) -> CommandFileAccesses {
        self.network_write_git()
    }

    fn resolve(&self, path: &str) -> String {
        resolve(path, &self.work_tree)
    }
}

impl CommandParser for GitParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let GlobalOptions {
            ctx,
            subcmd,
            sub_args,
            has_config_override,
            is_informational,
        } = parse_global_options(args, cwd);

        // `-c key=value` can set config keys that execute arbitrary code
        // (core.pager, diff.external, alias.*, core.hooksPath, etc.) — including
        // aliases that intercept any subcommand (even `--version`). Always
        // require a Bash rule when -c is present, before any other short-circuit.
        if has_config_override {
            return Ok(CommandFileAccesses::empty());
        }

        // Informational invocations (`git --version`, bare `git`, etc.) are
        // read-only.
        if is_informational {
            return Ok(ctx.read_only());
        }

        debug_assert!(
            !subcmd.is_empty(),
            "empty subcmd must have is_informational=true"
        );

        match subcmd {
            // Read-only subcommands -----
            "status" | "log" | "show" | "blame" | "rev-parse" | "ls-files" | "ls-tree"
            | "shortlog" | "describe" | "name-rev" | "grep" | "cherry" | "range-diff"
            | "whatchanged" | "check-ignore" | "help" | "version" => Ok(ctx.read_only()),

            "diff" => parse_diff(&ctx, sub_args),
            "branch" => parse_branch(&ctx, sub_args),
            "tag" => parse_tag(&ctx, sub_args),
            "remote" => parse_remote(&ctx, sub_args),
            "reflog" => parse_reflog(&ctx, sub_args),
            "stash" => parse_stash(&ctx, sub_args),
            "config" => parse_config(&ctx, sub_args),
            "symbolic-ref" => parse_symbolic_ref(&ctx, sub_args),
            "worktree" => parse_worktree(&ctx, sub_args),

            // Write .git only -----
            "add" | "commit" | "notes" => Ok(ctx.write_git()),

            "reset" => parse_reset(&ctx, sub_args),
            "rm" => parse_rm(&ctx, sub_args),

            // Write working tree -----
            "restore" => parse_restore(&ctx, sub_args),
            "checkout" => parse_checkout(&ctx, sub_args),
            "switch" => Ok(ctx.write_worktree_and_git()),
            // clean is destructive and we can't enumerate specific paths,
            // so fall through to requiring a Bash rule.
            "clean" => Ok(CommandFileAccesses::empty()),
            "merge" | "rebase" | "cherry-pick" | "revert" => Ok(ctx.write_worktree_and_git()),
            "mv" => parse_mv(&ctx, sub_args),
            "apply" => parse_apply(&ctx, sub_args),
            "init" => parse_init(sub_args, cwd),

            // Network operations -----
            "fetch" => Ok(ctx.network_write_git()),
            "pull" => Ok(ctx.network_write_worktree_and_git()),
            "push" => Ok(CommandFileAccesses {
                reads: vec![ctx.git_dir.clone()],
                writes: vec![],
                inline_script_start: None,
                file_only: Some(false),
                ..Default::default()
            }),
            "clone" => parse_clone(&ctx, sub_args),

            // Unknown → require Bash rule
            _ => Ok(CommandFileAccesses::empty()),
        }
    }
}

// Global option parsing =====

/// Parsed global options.
struct GlobalOptions<'a> {
    ctx: GitContext,
    subcmd: &'a str,
    sub_args: &'a [&'a str],
    /// True if `-c key=value` was seen. Forces a Bash rule because `-c` can
    /// set config keys that execute arbitrary code (core.pager, diff.external,
    /// alias.*, core.hooksPath, credential.helper, etc.).
    has_config_override: bool,
    /// True if an informational global flag (`--version`, `--help`, bare
    /// `--exec-path`, `--html-path`, `--man-path`, `--info-path`) was seen,
    /// or if no subcommand was provided (bare `git` prints help). These
    /// invocations are read-only and require no rules.
    is_informational: bool,
}

/// Parse global options before the subcommand. Always returns a
/// `GlobalOptions`: if no subcommand is found (or an informational flag like
/// `--version` is seen), `is_informational` is set and the caller treats it
/// as a read-only invocation.
fn parse_global_options<'a>(args: &'a [&'a str], cwd: &str) -> GlobalOptions<'a> {
    let mut effective_cwd = cwd.to_string();
    let mut git_dir: Option<String> = None;
    let mut work_tree: Option<String> = None;
    let mut has_config_override = false;
    let mut is_informational = false;
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if arg == "-C" {
            i += 1;
            if i < args.len() {
                effective_cwd = resolve(args[i], &effective_cwd);
            }
            i += 1;
            continue;
        }

        if arg == "-c" || arg.starts_with("-c") {
            // `-c key=value` or `-ckey=value`: can set dangerous config keys
            // (core.pager, diff.external, alias.*, etc.) that execute arbitrary
            // code.  Force a Bash rule for any command using -c.
            has_config_override = true;
            if arg == "-c" {
                i += 2; // consumes the next argument (key=value)
            } else {
                i += 1; // -ckey=value is a single arg
            }
            continue;
        }

        // --git-dir=<path> or --git-dir <path>
        if let Some(val) = arg.strip_prefix("--git-dir=") {
            git_dir = Some(resolve(val, &effective_cwd));
            i += 1;
            continue;
        }
        if arg == "--git-dir" {
            i += 1;
            if i < args.len() {
                git_dir = Some(resolve(args[i], &effective_cwd));
            }
            i += 1;
            continue;
        }

        // --work-tree=<path> or --work-tree <path>
        if let Some(val) = arg.strip_prefix("--work-tree=") {
            work_tree = Some(resolve(val, &effective_cwd));
            i += 1;
            continue;
        }
        if arg == "--work-tree" {
            i += 1;
            if i < args.len() {
                work_tree = Some(resolve(args[i], &effective_cwd));
            }
            i += 1;
            continue;
        }

        // Informational flags — read-only, no subcommand needed. Exact match
        // only: `--exec-path=<path>` is a setter and must fall through to the
        // `starts_with("--exec-path=")` branch below. `--html-path` /
        // `--man-path` / `--info-path` take no value at all.
        if matches!(
            arg,
            "--version"
                | "--help"
                | "--exec-path"
                | "--html-path"
                | "--man-path"
                | "--info-path"
        ) {
            is_informational = true;
            i += 1;
            continue;
        }

        // Boolean global flags
        if matches!(
            arg,
            "--no-pager"
                | "--paginate"
                | "--bare"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--no-optional-locks"
                | "-p"
                | "-P"
        ) {
            i += 1;
            continue;
        }

        // Value-taking flags with =
        if arg.starts_with("--namespace=")
            || arg.starts_with("--exec-path=")
            || arg.starts_with("--config-env=")
            || arg.starts_with("--super-prefix=")
        {
            i += 1;
            continue;
        }

        // First non-option arg is the subcommand
        break;
    }

    let wt = work_tree.unwrap_or_else(|| effective_cwd.clone());
    let gd = git_dir.unwrap_or_else(|| format!("{effective_cwd}/.git"));
    let ctx = GitContext {
        git_dir: gd,
        work_tree: wt,
    };

    if i >= args.len() {
        // No subcommand. If an informational flag was seen, or args is empty
        // (bare `git` prints help), treat as read-only.
        return GlobalOptions {
            ctx,
            subcmd: "",
            sub_args: &[],
            has_config_override,
            is_informational: true,
        };
    }

    let subcmd = args[i];
    let sub_args = &args[i + 1..];

    GlobalOptions {
        ctx,
        subcmd,
        sub_args,
        has_config_override,
        is_informational,
    }
}

// Subcommand parsers =====

fn parse_diff(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if let Some(val) = arg.strip_prefix("--output=") {
            return Ok(CommandFileAccesses {
                reads: vec![],
                writes: vec![ctx.resolve(val)],
                inline_script_start: None,
                file_only: Some(true),
                ..Default::default()
            });
        }
        if arg == "--output" {
            i += 1;
            if i < args.len() {
                return Ok(CommandFileAccesses {
                    reads: vec![],
                    writes: vec![ctx.resolve(args[i])],
                    inline_script_start: None,
                    file_only: Some(true),
                    ..Default::default()
                });
            }
        }
        i += 1;
    }
    Ok(ctx.read_only())
}

fn parse_branch(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        return Ok(ctx.read_only());
    }

    let has_positional = args.iter().any(|a| !a.starts_with('-'));

    // Check for mutation flags
    for arg in args {
        if matches!(
            *arg,
            "-d" | "-D" | "--delete" | "-m" | "-M" | "--move" | "-c" | "-C" | "--copy"
        ) {
            return Ok(ctx.write_git());
        }
    }

    // If there's a positional arg AND no explicit list flag, it's a branch
    // creation. `git branch -v new-branch` creates a branch (not list mode).
    if has_positional {
        let has_list_flag = args
            .iter()
            .any(|a| matches!(*a, "--list" | "-l" | "-a" | "--all" | "-r" | "--remotes"));
        if !has_list_flag {
            return Ok(ctx.write_git());
        }
    }

    Ok(ctx.read_only())
}

fn parse_tag(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        return Ok(ctx.read_only());
    }

    for arg in args {
        if matches!(*arg, "--list" | "-l") {
            return Ok(ctx.read_only());
        }
    }

    // Any flag or positional = creating/deleting a tag
    for arg in args {
        if matches!(*arg, "-d" | "--delete" | "-a" | "--annotate" | "-s" | "--sign") {
            return Ok(ctx.write_git());
        }
    }

    // Positional arg = creating a tag
    for arg in args {
        if !arg.starts_with('-') {
            return Ok(ctx.write_git());
        }
    }

    Ok(ctx.read_only())
}

fn parse_remote(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        return Ok(ctx.read_only());
    }

    let sub = args[0];

    // Read-only sub-subcommands (no network, no mutation)
    if matches!(sub, "get-url" | "-v" | "--verbose") {
        return Ok(ctx.read_only());
    }

    // `remote show` contacts the remote server. All other sub-subcommands
    // (add, remove, rename, set-url, prune, update, etc.) either access the
    // network or mutate .git. Default to network for unknown sub-subcommands.
    Ok(ctx.network_write_git())
}

fn parse_reflog(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        return Ok(ctx.read_only());
    }
    if matches!(args[0], "show") {
        return Ok(ctx.read_only());
    }
    // delete, expire, etc. → write .git
    Ok(ctx.write_git())
}

fn parse_stash(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        // bare `git stash` = stash push
        return Ok(ctx.write_git());
    }

    match args[0] {
        "list" | "show" => Ok(ctx.read_only()),
        "pop" | "apply" => Ok(ctx.write_worktree_and_git()),
        "push" | "save" | "create" | "store" | "drop" | "clear" => Ok(ctx.write_git()),
        // Unknown stash sub-subcommand → conservative: write .git
        _ => Ok(ctx.write_git()),
    }
}

fn parse_reset(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    for arg in args {
        if *arg == "--hard" {
            return Ok(ctx.write_worktree_and_git());
        }
    }
    Ok(ctx.write_git())
}

fn parse_rm(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    let mut cached = false;
    let mut paths = Vec::new();

    for arg in args {
        if matches!(*arg, "--cached") {
            cached = true;
        } else if *arg == "-r" || *arg == "--recursive" || *arg == "-f" || *arg == "--force" {
            // skip flags
        } else if *arg == "--" {
            // skip separator
        } else if !arg.starts_with('-') {
            paths.push(ctx.resolve(arg));
        }
    }

    if cached {
        Ok(ctx.write_git())
    } else {
        let mut writes: Vec<String> = paths;
        writes.push(ctx.git_dir.clone());
        Ok(CommandFileAccesses {
            reads: vec![],
            writes,
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        })
    }
}

fn parse_restore(ctx: &GitContext, _args: &[&str]) -> Result<CommandFileAccesses, String> {
    // `restore` takes pathspecs which may be patterns or directory references
    // (like `.`).  We can't reliably check these against Write rules, so we
    // only emit Write(.git) as the permission anchor — the same approach used
    // by other whole-tree operations (checkout, merge, etc.).
    Ok(ctx.write_git())
}

fn parse_checkout(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    // Look for `--` separator → file restore mode
    if let Some(sep_pos) = args.iter().position(|a| *a == "--") {
        let paths_after = &args[sep_pos + 1..];
        let mut writes: Vec<String> = paths_after.iter().map(|p| ctx.resolve(p)).collect();
        writes.push(ctx.git_dir.clone());
        return Ok(CommandFileAccesses {
            reads: vec![],
            writes,
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        });
    }

    // -b / -B / --orphan → branch creation/switch (writes whole tree)
    for arg in args {
        if matches!(*arg, "-b" | "-B" | "--orphan") {
            return Ok(ctx.write_worktree_and_git());
        }
    }

    // Default: treat as branch switch (conservative)
    Ok(ctx.write_worktree_and_git())
}

fn parse_mv(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    // Collect positional args (skip flags)
    let positionals: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .copied()
        .collect();

    if positionals.len() >= 2 {
        let src = ctx.resolve(positionals[0]);
        let dst = ctx.resolve(positionals[positionals.len() - 1]);
        Ok(CommandFileAccesses {
            reads: vec![src],
            writes: vec![dst, ctx.git_dir.clone()],
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        })
    } else {
        // Incomplete args → just write .git
        Ok(ctx.write_git())
    }
}

fn parse_apply(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    for arg in args {
        if matches!(*arg, "--stat" | "--check" | "--summary" | "--numstat") {
            return Ok(ctx.read_only());
        }
    }
    // `apply` modifies working-tree files but we can't enumerate which ones.
    // Require a Bash rule (same rationale as `clean`).
    Ok(CommandFileAccesses::empty())
}

fn parse_init(args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
    // Collect positional args (skip flags like --bare, --template, etc.)
    let mut dir: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--template" || arg == "--separate-git-dir" {
            i += 2; // skip flag + value
            continue;
        }
        if arg.starts_with("--template=")
            || arg.starts_with("--separate-git-dir=")
            || arg.starts_with("--initial-branch=")
            || arg.starts_with("-b")
        {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        dir = Some(arg);
        i += 1;
    }

    let target = match dir {
        Some(d) => format!("{}/.git", resolve(d, cwd)),
        None => format!("{cwd}/.git"),
    };

    Ok(CommandFileAccesses {
        reads: vec![],
        writes: vec![target],
        inline_script_start: None,
        file_only: Some(true),
        ..Default::default()
    })
}

fn parse_clone(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    // Collect positional args (url, optional dir)
    let mut positionals = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        // Skip value-taking flags
        if matches!(
            arg,
            "-b"
                | "--branch"
                | "--depth"
                | "--jobs"
                | "-j"
                | "--reference"
                | "--reference-if-able"
                | "--origin"
                | "-o"
                | "--template"
                | "--separate-git-dir"
                | "--filter"
                | "--config"
                | "-c"
        ) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        positionals.push(arg);
        i += 1;
    }

    let target = if positionals.len() >= 2 {
        // Explicit directory
        ctx.resolve(positionals[1])
    } else {
        // No directory given → conservative: writes to cwd
        ctx.work_tree.clone()
    };

    Ok(CommandFileAccesses {
        reads: vec![],
        writes: vec![target],
        inline_script_start: None,
        file_only: Some(false),
        ..Default::default()
    })
}

// Worktree =====

fn parse_worktree(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        // Bare `git worktree` prints help
        return Ok(ctx.read_only());
    }

    // `git worktree --help` / `-h` prints help.
    if matches!(args[0], "--help" | "-h") {
        return Ok(ctx.read_only());
    }

    // `git worktree <sub> --help` / `-h` — only matched when `--help` is
    // immediately after the sub-subcommand, not later. This is the common
    // case users actually type. Later positions can't safely be scanned
    // because `--help` might be the value of a value-taking flag (e.g.
    // `worktree add --reason --help /path`).
    if args.len() >= 2 && matches!(args[1], "--help" | "-h") {
        return Ok(ctx.read_only());
    }

    match args[0] {
        "list" => Ok(ctx.read_only()),
        "add" => parse_worktree_add(ctx, &args[1..]),
        "remove" | "rm" => parse_worktree_remove(ctx, &args[1..]),
        "move" | "mv" => parse_worktree_move(ctx, &args[1..]),
        "lock" | "unlock" | "repair" | "prune" => Ok(ctx.write_git()),
        // Unknown sub-subcommand → require Bash rule
        _ => Ok(CommandFileAccesses::empty()),
    }
}

fn parse_worktree_add(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    let mut positionals = Vec::new();
    let mut i = 0;
    let mut past_separator = false;

    while i < args.len() {
        let arg = args[i];

        if past_separator {
            positionals.push(arg);
            i += 1;
            continue;
        }

        if arg == "--" {
            past_separator = true;
            i += 1;
            continue;
        }

        // Value-taking flags (skip flag + value)
        if matches!(arg, "-b" | "-B" | "--reason") {
            i += 2;
            continue;
        }

        // Boolean flags (skip 1)
        if matches!(
            arg,
            "-f" | "--force"
                | "--detach"
                | "--checkout"
                | "--no-checkout"
                | "--lock"
                | "--no-lock"
                | "--no-track"
                | "--guess-remote"
                | "--no-guess-remote"
                | "--relative-paths"
                | "-q"
                | "--quiet"
                | "--orphan"
        ) {
            i += 1;
            continue;
        }

        // Unknown flag: fall back to a Bash rule. An unknown value-taking
        // flag would otherwise silently steal positional[0] (the path), and
        // the real path would be pushed off to positional[1] and dropped.
        // This is safer than silently skipping — the user can add a one-off
        // Bash rule if they need a flag we don't recognize.
        if arg.starts_with('-') {
            return Ok(CommandFileAccesses::empty());
        }

        positionals.push(arg);
        i += 1;
    }

    if positionals.is_empty() {
        // Incomplete args → conservative
        return Ok(ctx.write_git());
    }

    // Only positionals[0] is the path. positionals[1] (if present) is a
    // commit-ish (branch, tag, HEAD~1) — NOT a path.
    Ok(CommandFileAccesses {
        reads: vec![],
        writes: vec![ctx.resolve(positionals[0]), ctx.git_dir.clone()],
        inline_script_start: None,
        file_only: Some(true),
        ..Default::default()
    })
}

fn parse_worktree_remove(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    let mut path: Option<&str> = None;
    let mut i = 0;
    let mut past_separator = false;

    while i < args.len() {
        let arg = args[i];

        if past_separator {
            if path.is_none() {
                path = Some(arg);
            }
            i += 1;
            continue;
        }

        if arg == "--" {
            past_separator = true;
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            // -f/--force or any other flag: skip
            i += 1;
            continue;
        }

        if path.is_none() {
            path = Some(arg);
        }
        i += 1;
    }

    match path {
        Some(p) => Ok(CommandFileAccesses {
            reads: vec![],
            writes: vec![ctx.resolve(p), ctx.git_dir.clone()],
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        }),
        None => Ok(ctx.write_git()),
    }
}

fn parse_worktree_move(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    let positionals: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .copied()
        .collect();

    if positionals.len() >= 2 {
        Ok(CommandFileAccesses {
            reads: vec![ctx.resolve(positionals[0])],
            writes: vec![ctx.resolve(positionals[1]), ctx.git_dir.clone()],
            inline_script_start: None,
            file_only: Some(true),
            ..Default::default()
        })
    } else {
        Ok(ctx.write_git())
    }
}

// Config =====

fn parse_config(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    if args.is_empty() {
        // Bare `git config` prints help
        return Ok(ctx.read_only());
    }

    let mut file_paths: Vec<String> = Vec::new();
    let mut is_explicit_read = false;
    let mut is_explicit_write = false;
    let mut positional_values: Vec<&str> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        // --file <path> / -f <path> / --file=<path>. Record the path —
        // whether it's emitted as Read or Write depends on the action
        // determined after the scan.
        if arg == "-f" || arg == "--file" {
            i += 1;
            if i < args.len() {
                file_paths.push(ctx.resolve(args[i]));
            }
            i += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--file=") {
            file_paths.push(ctx.resolve(val));
            i += 1;
            continue;
        }

        // --blob <ref> — not a filesystem path, skip value
        if arg == "--blob" {
            i += 2;
            continue;
        }
        if arg.starts_with("--blob=") {
            i += 1;
            continue;
        }

        // Value-taking flags (skip value, no file access)
        if arg == "--type" || arg == "--default" {
            i += 2;
            continue;
        }
        if arg.starts_with("--type=") || arg.starts_with("--default=") {
            i += 1;
            continue;
        }

        // Explicit reads
        if matches!(
            arg,
            "--get"
                | "--get-all"
                | "--get-regexp"
                | "--get-urlmatch"
                | "--get-color"
                | "--get-colorbool"
                | "--list"
                | "-l"
        ) {
            is_explicit_read = true;
            i += 1;
            continue;
        }

        // Explicit writes
        if matches!(
            arg,
            "--unset"
                | "--unset-all"
                | "--add"
                | "--replace-all"
                | "--rename-section"
                | "--remove-section"
                | "-e"
                | "--edit"
        ) {
            is_explicit_write = true;
            i += 1;
            continue;
        }

        // Scope / formatting booleans
        if matches!(
            arg,
            "--global"
                | "--system"
                | "--local"
                | "--worktree"
                | "--includes"
                | "--no-includes"
                | "--show-origin"
                | "--show-scope"
                | "--name-only"
                | "--null"
                | "-z"
                | "--bool"
                | "--int"
                | "--path"
                | "--expiry-date"
                | "--bool-or-int"
                | "--bool-or-str"
        ) {
            i += 1;
            continue;
        }

        if !arg.starts_with('-') {
            positional_values.push(arg);
            i += 1;
            continue;
        }

        // Unknown flag: skip conservatively
        i += 1;
    }

    // Git >= 2.46 subcommand-form writers. `edit` in particular opens $EDITOR
    // (arbitrary code execution). Must NOT be misclassified as a read. We
    // check all positionals (not just args[0]) because scope flags like
    // `--global`, `--file <path>` can precede the subcommand — e.g.
    // `git config --global edit` or `git config --file /etc/secret edit`.
    //
    // We deliberately do NOT recognize `get` / `list` / `get-regexp` as
    // readers. In git < 2.46, `git config get foo.bar` is a SETTER. The
    // 2-positional-setter branch below handles both cases safely.
    if positional_values.iter().any(|p| {
        matches!(
            *p,
            "edit"
                | "set"
                | "set-all"
                | "unset"
                | "unset-all"
                | "add"
                | "replace-all"
                | "rename-section"
                | "remove-section"
        )
    }) {
        is_explicit_write = true;
    }

    let positionals = positional_values.len();

    // Helper: build a return value with the collected --file paths.
    // When the action is a write, the --file path is BOTH read (git parses
    // it to modify) AND written — emit in both vectors so either
    // Deny(Read(<path>)) or Deny(Write(<path>)) can match.
    // file_only=Some(false) means "Bash rule also required" (treating this
    // like a network side-effect from a permission-matching standpoint).
    let emit_with_paths = |kind: AccessIntent| -> CommandFileAccesses {
        match kind {
            AccessIntent::Read => CommandFileAccesses {
                reads: file_paths.clone(),
                writes: vec![],
                inline_script_start: None,
                file_only: Some(true),
                ..Default::default()
            },
            AccessIntent::Write => CommandFileAccesses {
                reads: file_paths.clone(),
                writes: file_paths.clone(),
                inline_script_start: None,
                file_only: Some(false),
                ..Default::default()
            },
        }
    };

    // Ordering matters:
    //   1. explicit write → Bash rule (with --file paths plumbed through
    //                      as BOTH reads and writes for deny matching)
    //   2. explicit read  → read (even with 2+ positionals, e.g.
    //                       `--get foo.bar pattern` or `--get-urlmatch foo URL`)
    //   3. 2+ positionals with no explicit action → Bash rule
    //      (setter form `foo.bar value`)
    //   4. 1 positional  → read (bare `git config <key>`)
    //   5. 0 positionals → read

    if is_explicit_write {
        if file_paths.is_empty() {
            return Ok(CommandFileAccesses::empty());
        }
        return Ok(emit_with_paths(AccessIntent::Write));
    }

    if is_explicit_read {
        if file_paths.is_empty() {
            return Ok(ctx.read_only());
        }
        return Ok(emit_with_paths(AccessIntent::Read));
    }

    if positionals >= 2 {
        if file_paths.is_empty() {
            return Ok(CommandFileAccesses::empty());
        }
        return Ok(emit_with_paths(AccessIntent::Write));
    }

    if positionals == 1 {
        if file_paths.is_empty() {
            return Ok(ctx.read_only());
        }
        return Ok(emit_with_paths(AccessIntent::Read));
    }

    // No positional, no explicit action. Scope-only invocations
    // (e.g. `git config --global`) are no-ops; `--file <path>` alone reads.
    if file_paths.is_empty() {
        Ok(ctx.read_only())
    } else {
        Ok(emit_with_paths(AccessIntent::Read))
    }
}

enum AccessIntent {
    Read,
    Write,
}

// Symbolic-ref =====

fn parse_symbolic_ref(ctx: &GitContext, args: &[&str]) -> Result<CommandFileAccesses, String> {
    let mut positionals: u32 = 0;
    let mut i = 0;

    while i < args.len() {
        let arg = args[i];

        if matches!(arg, "-d" | "--delete") {
            return Ok(ctx.write_git());
        }

        if arg == "-m" {
            i += 2; // value-taking
            continue;
        }

        if matches!(arg, "-q" | "--quiet" | "--short") {
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            i += 1;
            continue;
        }

        positionals += 1;
        i += 1;
    }

    match positionals {
        0 | 1 => Ok(ctx.read_only()),
        _ => Ok(ctx.write_git()),
    }
}
