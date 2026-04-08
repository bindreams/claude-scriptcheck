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
fn submodule_is_unknown() {
    let result = GitParser.parse(&["submodule", "update"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

// Edge cases =====

#[skuld::test]
fn no_args_is_informational() {
    // Bare `git` prints help — read-only, no rules needed.
    let result = GitParser.parse(&[], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.reads.is_empty());
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn only_global_flags_no_subcommand_is_informational() {
    // `git --no-pager` with no subcommand prints help — read-only.
    let result = GitParser.parse(&["--no-pager"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
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

// Informational global flags =====

#[skuld::test]
fn version_flag_is_read_only() {
    let result = GitParser.parse(&["--version"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn help_flag_is_read_only() {
    let result = GitParser.parse(&["--help"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn exec_path_bare_is_read_only() {
    let result = GitParser.parse(&["--exec-path"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn exec_path_with_value_falls_through_to_subcommand() {
    // `git --exec-path=/foo status` — the `=` form is a setter, not
    // informational, and must dispatch to `status` (which is read-only).
    let result = GitParser
        .parse(&["--exec-path=/foo", "status"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn html_path_is_read_only() {
    let result = GitParser.parse(&["--html-path"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn man_path_is_read_only() {
    let result = GitParser.parse(&["--man-path"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn info_path_is_read_only() {
    let result = GitParser.parse(&["--info-path"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn dash_c_with_informational() {
    // `git -C /other --version` — -C is parsed, then --version is informational.
    let result = GitParser
        .parse(&["-C", "/other", "--version"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn dash_lowercase_c_overrides_informational() {
    // -c can register aliases that intercept even --version, so it must
    // always force a Bash rule regardless of informational flags.
    let result = GitParser
        .parse(&["-c", "alias.v=version", "--version"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

// Worktree =====

#[skuld::test]
fn worktree_bare_is_read_only() {
    let result = GitParser.parse(&["worktree"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn worktree_list_is_read_only() {
    let result = GitParser.parse(&["worktree", "list"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn worktree_add_path_only() {
    let result = GitParser
        .parse(&["worktree", "add", ".worktrees/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_absolute_path() {
    let result = GitParser
        .parse(&["worktree", "add", "/other/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/other/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_with_branch_flag() {
    let result = GitParser
        .parse(
            &["worktree", "add", "-b", "branch", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_with_commit_ish() {
    // `git worktree add <path> <commit-ish>` — HEAD~1 is a commit-ish,
    // NOT a path. Must not be in writes. This is the critical regression
    // test against mimicking parse_mv's `positionals[len-1]` pattern.
    let result = GitParser
        .parse(&["worktree", "add", ".worktrees/foo", "HEAD~1"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
    assert!(!result.writes.iter().any(|p| p.contains("HEAD")));
}

#[skuld::test]
fn worktree_add_detach_with_commit_ish() {
    let result = GitParser
        .parse(
            &["worktree", "add", "--detach", ".worktrees/foo", "HEAD~1"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_with_branch_name_positional() {
    let result = GitParser
        .parse(&["worktree", "add", ".worktrees/foo", "main"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_remove() {
    let result = GitParser
        .parse(&["worktree", "remove", ".worktrees/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_remove_force() {
    let result = GitParser
        .parse(&["worktree", "remove", "-f", ".worktrees/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_move() {
    let result = GitParser
        .parse(
            &["worktree", "move", ".worktrees/a", ".worktrees/b"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.reads, r(&["/repo/.worktrees/a"]));
    assert_eq!(result.writes, w(&["/repo/.worktrees/b", "/repo/.git"]));
}

#[skuld::test]
fn worktree_lock_is_write_git() {
    let result = GitParser
        .parse(&["worktree", "lock", ".worktrees/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_prune_is_write_git() {
    let result = GitParser.parse(&["worktree", "prune"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_unknown_sub_sub_requires_bash_rule() {
    let result = GitParser
        .parse(&["worktree", "frobnicate"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

// Config =====

#[skuld::test]
fn config_bare_key_is_read() {
    // `git config core.symlinks` — 1 positional = read
    let result = GitParser
        .parse(&["config", "core.symlinks"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn config_get_flag_is_read() {
    let result = GitParser
        .parse(&["config", "--get", "foo.bar"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_list_is_read() {
    let result = GitParser.parse(&["config", "--list"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_file_space_separated_emits_read() {
    let result = GitParser
        .parse(
            &["config", "--file", ".gitmodules", "--get-regexp", "path"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.reads, r(&["/repo/.gitmodules"]));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_file_equals_form_emits_read() {
    let result = GitParser
        .parse(&["config", "--file=.gitmodules", "--get", "foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.reads, r(&["/repo/.gitmodules"]));
}

#[skuld::test]
fn config_blob_is_not_a_file_path() {
    // `--blob HEAD:config` is a git blob ref, not a filesystem path.
    // Must NOT emit a Read.
    let result = GitParser
        .parse(&["config", "--blob", "HEAD:config", "--get", "foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn config_global_read() {
    let result = GitParser
        .parse(&["config", "--global", "user.name"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_global_write_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "--global", "user.name", "Alice"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_unset_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "--unset", "foo.bar"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_key_value_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "foo.bar", "value"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_edit_requires_bash_rule() {
    let result = GitParser.parse(&["config", "--edit"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_new_subcommand_form_get_is_not_recognized() {
    // git >= 2.46 subcommand form: `git config get foo.bar`. We deliberately
    // do NOT recognize this (old git interprets it as a setter — semantic
    // inversion risk). Falls through to flag-form scan: 2 positionals = write.
    let result = GitParser
        .parse(&["config", "get", "foo.bar"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_new_subcommand_form_set_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "set", "foo.bar", "value"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_bare_is_read_only() {
    let result = GitParser.parse(&["config"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_with_dash_lowercase_c_override_requires_bash_rule() {
    // `git -c foo=bar config --get baz` — the top-level -c short-circuit
    // must fire before parse_config is called.
    let result = GitParser
        .parse(&["-c", "alias.foo=bar", "config", "--get", "x"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

// Symbolic-ref =====

#[skuld::test]
fn symbolic_ref_read_head() {
    let result = GitParser
        .parse(&["symbolic-ref", "HEAD"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn symbolic_ref_read_origin_head() {
    let result = GitParser
        .parse(&["symbolic-ref", "refs/remotes/origin/HEAD"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn symbolic_ref_short_read() {
    let result = GitParser
        .parse(&["symbolic-ref", "--short", "HEAD"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn symbolic_ref_set_is_write() {
    let result = GitParser
        .parse(&["symbolic-ref", "HEAD", "refs/heads/main"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn symbolic_ref_set_with_reason() {
    // -m <reason> is value-taking. After skipping, 2 positionals → write.
    let result = GitParser
        .parse(
            &["symbolic-ref", "-m", "reason", "HEAD", "refs/heads/main"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn symbolic_ref_delete() {
    let result = GitParser
        .parse(&["symbolic-ref", "-d", "HEAD"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn symbolic_ref_delete_long() {
    let result = GitParser
        .parse(&["symbolic-ref", "--delete", "HEAD"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn symbolic_ref_bare_is_read_only() {
    // GAP 15: 0 positionals → read_only
    let result = GitParser.parse(&["symbolic-ref"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn symbolic_ref_read_with_reason() {
    // GAP 16: `-m <reason>` + 1 positional = read (not write).
    // Verifies -m's value isn't miscounted as a positional.
    let result = GitParser
        .parse(&["symbolic-ref", "-m", "reason", "HEAD"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

// Bug regression tests =====

#[skuld::test]
fn config_get_with_value_pattern_is_read() {
    // BUG 1 regression: `git config --get foo.bar pattern` is a READ
    // (the 2nd positional is a value pattern to filter by), not a write.
    let result = GitParser
        .parse(&["config", "--get", "foo.bar", "pattern"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_get_regexp_with_value_pattern_is_read() {
    // BUG 1 regression: same for --get-regexp
    let result = GitParser
        .parse(
            &["config", "--get-regexp", "^remote\\.", "origin"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_get_urlmatch_is_read() {
    // BUG 1 regression: --get-urlmatch requires 2 positionals.
    let result = GitParser
        .parse(
            &["config", "--get-urlmatch", "http", "https://example.com"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_file_with_write_still_emits_read_for_deny_matching() {
    // BUG 2 regression: `git config --file /etc/secret --unset foo.bar` —
    // the --file read must still be plumbed through so Deny(Read) can match.
    // Because the action is a write, file_only=false (Bash rule also required).
    let result = GitParser
        .parse(
            &["config", "--file", "/etc/secret", "--unset", "foo.bar"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.reads, r(&["/etc/secret"]));
}

#[skuld::test]
fn config_file_with_no_action_still_emits_read() {
    // BUG 3 regression: `git config --file /etc/secret` alone has no explicit
    // action and no positional, but the --file read must still be emitted.
    let result = GitParser
        .parse(&["config", "--file", "/etc/secret"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.reads, r(&["/etc/secret"]));
}

#[skuld::test]
fn config_edit_subcommand_form_requires_bash_rule() {
    // BUG 7 regression: `git config edit` (git >= 2.46 subcommand form)
    // opens $EDITOR = arbitrary code execution. MUST NOT be classified as
    // a read via the 1-positional heuristic.
    let result = GitParser.parse(&["config", "edit"], "/repo").unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_unset_subcommand_form_requires_bash_rule() {
    // BUG 7 regression: `git config unset foo.bar` (git >= 2.46). Also
    // caught by positionals>=2, but the explicit top-of-function guard
    // makes this immune to refactoring.
    let result = GitParser
        .parse(&["config", "unset", "foo.bar"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_add_subcommand_form_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "add", "foo.bar", "value"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn worktree_add_unknown_flag_requires_bash_rule() {
    // BUG 4 regression: an unknown flag may be value-taking. We must not
    // silently skip it and risk stealing positional[0] (the worktree path).
    // Fall back to Bash rule.
    let result = GitParser
        .parse(
            &["worktree", "add", "--future-flag", "value", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn worktree_add_no_lock_is_skipped() {
    // Verifies --no-lock is recognized as a boolean (regression for the
    // flag list fix).
    let result = GitParser
        .parse(
            &["worktree", "add", "--no-lock", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_help_is_read_only() {
    // BUG 5 regression: `git worktree --help` prints help.
    let result = GitParser.parse(&["worktree", "--help"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn worktree_h_short_is_read_only() {
    let result = GitParser.parse(&["worktree", "-h"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn worktree_add_help_is_read_only() {
    // BUG 6 regression: `git worktree add --help` prints help — must not
    // require a Write rule.
    let result = GitParser
        .parse(&["worktree", "add", "--help"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn worktree_remove_help_is_read_only() {
    let result = GitParser
        .parse(&["worktree", "remove", "--help"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn worktree_move_help_is_read_only() {
    let result = GitParser
        .parse(&["worktree", "move", "--help"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

// Test gap fills =====

#[skuld::test]
fn worktree_rm_alias() {
    // GAP 5: `rm` is an alias for `remove`
    let result = GitParser
        .parse(&["worktree", "rm", ".worktrees/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_mv_alias() {
    // GAP 5: `mv` is an alias for `move`
    let result = GitParser
        .parse(
            &["worktree", "mv", ".worktrees/a", ".worktrees/b"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/b", "/repo/.git"]));
}

#[skuld::test]
fn worktree_unlock_is_write_git() {
    // GAP 6
    let result = GitParser
        .parse(&["worktree", "unlock", ".worktrees/foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_repair_is_write_git() {
    // GAP 6
    let result = GitParser.parse(&["worktree", "repair"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_add_separator_locks_in_path_semantics() {
    // GAP 7: `--` separator, only positionals[0] is the path.
    let result = GitParser
        .parse(
            &["worktree", "add", "--", ".worktrees/foo", "HEAD~1"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_no_positional_is_write_git() {
    // GAP 8
    let result = GitParser.parse(&["worktree", "add"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_remove_no_positional_is_write_git() {
    // GAP 9
    let result = GitParser.parse(&["worktree", "remove"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_move_one_positional_is_write_git() {
    // GAP 10
    let result = GitParser
        .parse(&["worktree", "move", ".worktrees/a"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.git"]));
}

#[skuld::test]
fn worktree_add_with_capital_b_flag() {
    // GAP 17: -B is value-taking too
    let result = GitParser
        .parse(
            &["worktree", "add", "-B", "branch", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn config_dash_f_short_form_emits_read() {
    // GAP 11: `-f <path>` is the short form of `--file`
    let result = GitParser
        .parse(&["config", "-f", ".gitmodules", "--get", "foo"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.reads, r(&["/repo/.gitmodules"]));
}

#[skuld::test]
fn config_dash_l_short_form_is_read() {
    // GAP 12: `-l` is the short form of `--list`
    let result = GitParser.parse(&["config", "-l"], "/repo").unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_blob_equals_form() {
    // GAP 13: `--blob=HEAD:config`
    let result = GitParser
        .parse(
            &["config", "--blob=HEAD:config", "--get", "foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.reads.is_empty());
}

#[skuld::test]
fn config_type_flag_skips_value() {
    // GAP 14: `--type <type>` is value-taking; must not steal positional.
    let result = GitParser
        .parse(&["config", "--type", "bool", "foo.bar"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn config_default_flag_skips_value() {
    // GAP 14: `--default <value>` is value-taking.
    let result = GitParser
        .parse(
            &["config", "--default", "fallback", "--get", "foo.bar"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}

#[skuld::test]
fn informational_version_then_dash_c() {
    // GAP 1 (from review): reverse order of -c and --version
    let result = GitParser
        .parse(&["--version", "-c", "alias.v=version"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

// Second-round bug regression tests =====

#[skuld::test]
fn config_global_edit_requires_bash_rule() {
    // BUG 8 regression: `git config --global edit` — scope flag before
    // subcommand-form `edit` must still be caught.
    let result = GitParser
        .parse(&["config", "--global", "edit"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_system_edit_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "--system", "edit"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_local_edit_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "--local", "edit"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_worktree_edit_requires_bash_rule() {
    let result = GitParser
        .parse(&["config", "--worktree", "edit"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, None);
}

#[skuld::test]
fn config_file_edit_is_write_with_path_emitted() {
    // BUG 8 + BUG 11 regression: `git config --file /etc/secret edit`
    // opens $EDITOR on /etc/secret. Must be a write AND emit the path
    // as both read and write for deny matching.
    let result = GitParser
        .parse(&["config", "--file", "/etc/secret", "edit"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.reads, r(&["/etc/secret"]));
    assert_eq!(result.writes, w(&["/etc/secret"]));
}

#[skuld::test]
fn config_file_write_emits_path_as_write() {
    // BUG 10 regression: `git config --file /etc/secret --unset foo.bar`
    // is a write TO /etc/secret. Deny(Write(/etc/secret)) must be able
    // to match, so the path must be in `writes`, not only `reads`.
    let result = GitParser
        .parse(
            &["config", "--file", "/etc/secret", "--unset", "foo.bar"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(false));
    assert_eq!(result.reads, r(&["/etc/secret"]));
    assert_eq!(result.writes, w(&["/etc/secret"]));
}

#[skuld::test]
fn worktree_add_reason_value_containing_dash_h_is_not_help() {
    // BUG 9 regression: `-h` is the value of `--reason`, not a help flag.
    // Must not falsely classify as read-only.
    let result = GitParser
        .parse(
            &["worktree", "add", "--reason", "-h", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_b_flag_value_dash_h_is_not_help() {
    // BUG 9 regression: `-h` as branch name via `-b -h`.
    let result = GitParser
        .parse(
            &["worktree", "add", "-b", "-h", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_reason_dash_dash_help_as_value() {
    // BUG 9 regression: `--reason --help /path` — --help is --reason's
    // value. git might actually error on this, but our parser must be
    // safe — treat as a normal add (write), not as help (read).
    let result = GitParser
        .parse(
            &["worktree", "add", "--reason", "--help", ".worktrees/foo"],
            "/repo",
        )
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/.worktrees/foo", "/repo/.git"]));
}

#[skuld::test]
fn worktree_add_dash_dash_help_as_path() {
    // BUG 9 regression: `git worktree add -- --help` creates a worktree
    // at path `--help`. Not help. Must write.
    let result = GitParser
        .parse(&["worktree", "add", "--", "--help"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert_eq!(result.writes, w(&["/repo/--help", "/repo/.git"]));
}

#[skuld::test]
fn worktree_list_help_is_read_only() {
    // Sanity: `worktree list --help` is read_only (narrow scan still
    // catches it because --help is at args[1]).
    let result = GitParser
        .parse(&["worktree", "list", "--help"], "/repo")
        .unwrap();
    assert_eq!(result.file_only, Some(true));
    assert!(result.writes.is_empty());
}
