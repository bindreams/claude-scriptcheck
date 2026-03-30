use super::git::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn r(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn w(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

// Read-only subcommands =====

#[skuld::test]
fn status_is_read_only() {
    let result = GitParser.parse(&["status"], "/repo").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn status_with_flags() {
    let result = GitParser.parse(&["status", "-s", "--branch"], "/repo").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn log_is_read_only() {
    let result = GitParser.parse(&["log", "--oneline", "-10"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn diff_is_read_only() {
    let result = GitParser.parse(&["diff"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn diff_output_writes_file() {
    let result = GitParser.parse(&["diff", "--output=out.patch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/out.patch"]));
}

#[skuld::test]
fn diff_output_space_writes_file() {
    let result = GitParser.parse(&["diff", "--output", "out.patch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/out.patch"]));
}

#[skuld::test]
fn show_is_read_only() {
    let result = GitParser.parse(&["show", "HEAD"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn blame_is_read_only() {
    let result = GitParser.parse(&["blame", "file.rs"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn rev_parse_is_read_only() {
    let result = GitParser.parse(&["rev-parse", "HEAD"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn ls_files_is_read_only() {
    let result = GitParser.parse(&["ls-files"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn shortlog_is_read_only() {
    let result = GitParser.parse(&["shortlog", "-sn"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn describe_is_read_only() {
    let result = GitParser.parse(&["describe", "--tags"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn grep_is_read_only() {
    let result = GitParser.parse(&["grep", "pattern"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

// Branch/tag listing =====

#[skuld::test]
fn branch_no_args_is_read_only() {
    let result = GitParser.parse(&["branch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn branch_list_flag() {
    let result = GitParser.parse(&["branch", "--list"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn branch_all_flag() {
    let result = GitParser.parse(&["branch", "-a"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn branch_remote_flag() {
    let result = GitParser.parse(&["branch", "-r"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn tag_no_args_is_read_only() {
    let result = GitParser.parse(&["tag"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn tag_list_flag() {
    let result = GitParser.parse(&["tag", "--list"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn tag_list_short_flag() {
    let result = GitParser.parse(&["tag", "-l"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

// Remote =====

#[skuld::test]
fn remote_no_args_is_read_only() {
    let result = GitParser.parse(&["remote"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn remote_verbose() {
    let result = GitParser.parse(&["remote", "-v"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn remote_show_is_network() {
    // `remote show` contacts the remote server
    let result = GitParser.parse(&["remote", "show", "origin"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn remote_get_url() {
    let result = GitParser.parse(&["remote", "get-url", "origin"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn remote_add_is_network() {
    let result = GitParser.parse(&["remote", "add", "origin", "url"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn remote_remove_is_network() {
    let result = GitParser.parse(&["remote", "remove", "origin"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

// Reflog / stash list =====

#[skuld::test]
fn reflog_no_args_is_read_only() {
    let result = GitParser.parse(&["reflog"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn reflog_show_is_read_only() {
    let result = GitParser.parse(&["reflog", "show"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

#[skuld::test]
fn stash_list_is_read_only() {
    let result = GitParser.parse(&["stash", "list"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn stash_show_is_read_only() {
    let result = GitParser.parse(&["stash", "show"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
}

// Write .git only =====

#[skuld::test]
fn add_writes_git() {
    let result = GitParser.parse(&["add", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn add_all_writes_git() {
    let result = GitParser.parse(&["add", "-A"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn commit_writes_git() {
    let result = GitParser.parse(&["commit", "-m", "msg"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn commit_amend_writes_git() {
    let result = GitParser.parse(&["commit", "--amend", "--no-edit"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn reset_default_writes_git() {
    let result = GitParser.parse(&["reset"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn reset_soft_writes_git() {
    let result = GitParser.parse(&["reset", "--soft", "HEAD~1"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn reset_mixed_writes_git() {
    let result = GitParser.parse(&["reset", "--mixed", "HEAD~1"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn rm_cached_writes_git_only() {
    let result = GitParser.parse(&["rm", "--cached", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn branch_create_writes_git() {
    let result = GitParser.parse(&["branch", "new-branch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn branch_delete_writes_git() {
    let result = GitParser.parse(&["branch", "-d", "old-branch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn branch_force_delete_writes_git() {
    let result = GitParser.parse(&["branch", "-D", "old-branch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn branch_rename_writes_git() {
    let result = GitParser.parse(&["branch", "-m", "old", "new"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn tag_create_writes_git() {
    let result = GitParser.parse(&["tag", "v1.0"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn tag_annotated_writes_git() {
    let result = GitParser.parse(&["tag", "-a", "v1.0", "-m", "release"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn tag_delete_writes_git() {
    let result = GitParser.parse(&["tag", "-d", "v1.0"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn stash_no_args_writes_git() {
    let result = GitParser.parse(&["stash"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn stash_push_writes_git() {
    let result = GitParser.parse(&["stash", "push"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn stash_drop_writes_git() {
    let result = GitParser.parse(&["stash", "drop"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn stash_clear_writes_git() {
    let result = GitParser.parse(&["stash", "clear"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn notes_writes_git() {
    let result = GitParser.parse(&["notes", "add", "-m", "note"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

// Write working tree =====

#[skuld::test]
fn restore_dot() {
    let result = GitParser.parse(&["restore", "."], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn restore_specific_file() {
    // restore takes pathspecs — we emit Write(.git) only
    let result = GitParser.parse(&["restore", "path/file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn restore_multiple_files() {
    let result = GitParser.parse(&["restore", "a.txt", "b.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn checkout_branch() {
    let result = GitParser.parse(&["checkout", "main"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn checkout_file_with_separator() {
    let result = GitParser.parse(&["checkout", "--", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.contains(&"/repo/file.txt".to_string()));
    assert!(result.writes.contains(&"/repo/.git".to_string()));
}

#[skuld::test]
fn checkout_ref_and_file() {
    let result = GitParser.parse(&["checkout", "HEAD~1", "--", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.contains(&"/repo/file.txt".to_string()));
    assert!(result.writes.contains(&"/repo/.git".to_string()));
}

#[skuld::test]
fn checkout_create_branch() {
    let result = GitParser.parse(&["checkout", "-b", "new-branch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn checkout_orphan() {
    let result = GitParser.parse(&["checkout", "--orphan", "new"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn switch_branch() {
    let result = GitParser.parse(&["switch", "main"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn clean_writes_cwd() {
    let result = GitParser.parse(&["clean", "-fd"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn reset_hard_writes_cwd_and_git() {
    let result = GitParser.parse(&["reset", "--hard"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn reset_hard_commit_writes_cwd_and_git() {
    let result = GitParser.parse(&["reset", "--hard", "HEAD~3"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn merge_writes_cwd_and_git() {
    let result = GitParser.parse(&["merge", "feature"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn rebase_writes_cwd_and_git() {
    let result = GitParser.parse(&["rebase", "main"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn cherry_pick_writes_cwd_and_git() {
    let result = GitParser.parse(&["cherry-pick", "abc123"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn revert_writes_cwd_and_git() {
    let result = GitParser.parse(&["revert", "abc123"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn stash_pop_writes_cwd_and_git() {
    let result = GitParser.parse(&["stash", "pop"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn stash_apply_writes_cwd_and_git() {
    let result = GitParser.parse(&["stash", "apply"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn rm_writes_paths_and_git() {
    let result = GitParser.parse(&["rm", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.contains(&"/repo/file.txt".to_string()));
    assert!(result.writes.contains(&"/repo/.git".to_string()));
}

#[skuld::test]
fn rm_recursive() {
    let result = GitParser.parse(&["rm", "-r", "dir/"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.contains(&"/repo/dir/".to_string()));
    assert!(result.writes.contains(&"/repo/.git".to_string()));
}

#[skuld::test]
fn mv_reads_src_writes_dst_and_git() {
    let result = GitParser.parse(&["mv", "a.txt", "b.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.reads, r(&["/repo/a.txt"]));
    assert!(result.writes.contains(&"/repo/b.txt".to_string()));
    assert!(result.writes.contains(&"/repo/.git".to_string()));
}

#[skuld::test]
fn apply_requires_bash_rule() {
    // apply modifies working tree but we can't enumerate paths → require Bash rule
    let result = GitParser.parse(&["apply", "patch.diff"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn apply_stat_is_read_only() {
    let result = GitParser.parse(&["apply", "--stat", "patch.diff"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn apply_check_is_read_only() {
    let result = GitParser.parse(&["apply", "--check", "patch.diff"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn init_no_dir() {
    let result = GitParser.parse(&["init"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn init_with_dir() {
    let result = GitParser.parse(&["init", "/path/to/dir"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/path/to/dir/.git"]));
}

#[skuld::test]
fn init_relative_dir() {
    let result = GitParser.parse(&["init", "subdir"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/subdir/.git"]));
}

// Network operations =====

#[skuld::test]
fn fetch_writes_git_not_file_only() {
    let result = GitParser.parse(&["fetch", "origin"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn fetch_with_branch() {
    let result = GitParser.parse(&["fetch", "origin", "main"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn pull_writes_cwd_and_git_not_file_only() {
    let result = GitParser.parse(&["pull"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn pull_rebase() {
    let result = GitParser.parse(&["pull", "--rebase"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn push_reads_git_not_file_only() {
    let result = GitParser.parse(&["push", "origin", "main"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.reads, r(&["/repo/.git"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn push_no_args() {
    let result = GitParser.parse(&["push"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.reads, r(&["/repo/.git"]));
}

#[skuld::test]
fn clone_with_dir() {
    let result = GitParser.parse(&["clone", "https://example.com/repo.git", "/tmp/dest"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/tmp/dest"]));
}

#[skuld::test]
fn clone_no_dir() {
    let result = GitParser.parse(&["clone", "https://example.com/repo.git"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo"]));
}

// Global option: -C =====

#[skuld::test]
fn c_flag_adjusts_cwd() {
    let result = GitParser.parse(&["-C", "/other/dir", "status"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    // Read-only, no accesses, but effective cwd changed
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn c_flag_affects_paths() {
    let result = GitParser.parse(&["-C", "/other/dir", "restore", "."], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.contains(&"/other/dir/.".to_string()) || result.writes.contains(&"/other/dir/.git".to_string()));
    assert!(result.writes.contains(&"/other/dir/.git".to_string()));
}

#[skuld::test]
fn c_flag_chained() {
    let result = GitParser.parse(&["-C", "/base", "-C", "sub", "add", "f.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/base/sub/.git"]));
}

// Global option: -c (config) =====

#[skuld::test]
fn c_config_forces_bash_rule() {
    // -c can set dangerous config keys (core.pager, diff.external, etc.)
    // so any git -c ... command must require a Bash rule
    let result = GitParser.parse(&["-c", "user.name=test", "status"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn c_config_inline_forces_bash_rule() {
    // -ckey=value (no space) also forces Bash rule
    let result = GitParser.parse(&["-ccore.pager=less", "log"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn c_config_dangerous_key() {
    // Even innocuous-looking commands become dangerous with -c
    let result = GitParser.parse(&["-c", "core.pager=evil", "log"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

// Global option: --git-dir =====

#[skuld::test]
fn git_dir_override() {
    let result = GitParser.parse(&["--git-dir=/other/.git", "add", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/other/.git"]));
}

#[skuld::test]
fn git_dir_space_separated() {
    let result = GitParser.parse(&["--git-dir", "/other/.git", "add", "file.txt"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/other/.git"]));
}

#[skuld::test]
fn git_dir_with_read_only_cmd() {
    let result = GitParser.parse(&["--git-dir=/other/.git", "status"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

// Global option: --work-tree =====

#[skuld::test]
fn work_tree_override() {
    let result = GitParser.parse(&["--work-tree=/other", "restore", "."], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    // git_dir still defaults to cwd/.git (not work_tree/.git)
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn work_tree_and_git_dir() {
    let result = GitParser.parse(
        &["--work-tree=/other", "--git-dir=/repo/.git", "fetch", "origin"],
        "/repo",
    ).unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

// Unknown subcommand =====

#[skuld::test]
fn unknown_subcommand_returns_empty() {
    let result = GitParser.parse(&["bisect", "start"], "/repo").unwrap();
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn worktree_is_unknown() {
    let result = GitParser.parse(&["worktree", "add", "/path"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn submodule_is_unknown() {
    let result = GitParser.parse(&["submodule", "update"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_is_unknown() {
    let result = GitParser.parse(&["config", "user.name"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

// Edge cases =====

#[skuld::test]
fn no_args_returns_empty() {
    let result = GitParser.parse(&[], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn only_global_flags_no_subcommand() {
    let result = GitParser.parse(&["--no-pager"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn merge_abort() {
    let result = GitParser.parse(&["merge", "--abort"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn rebase_continue() {
    let result = GitParser.parse(&["rebase", "--continue"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn cherry_pick_abort() {
    let result = GitParser.parse(&["cherry-pick", "--abort"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

// Bug fix tests =====

#[skuld::test]
fn branch_verbose_with_name_creates() {
    // `git branch -v new-branch` creates a branch, not lists
    let result = GitParser.parse(&["branch", "-v", "new-branch"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn remote_update_is_network() {
    let result = GitParser.parse(&["remote", "update"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn remote_unknown_subcommand_is_network() {
    // Unknown remote sub-subcommands default to network
    let result = GitParser.parse(&["remote", "foobar"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(false));
}
