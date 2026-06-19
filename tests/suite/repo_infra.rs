use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pretty_assertions::assert_eq;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(repo_root().join(path)).unwrap()
}

fn parse_json5(path: impl AsRef<Path>) -> Value {
    json5::from_str(&read(path)).unwrap()
}

fn parse_toml(path: impl AsRef<Path>) -> toml::Value {
    toml::from_str(&read(path)).unwrap()
}

fn parse_yaml(path: impl AsRef<Path>) -> Value {
    yaml_serde::from_str(&read(path)).unwrap()
}

fn local_hook_by_id<'a>(repos: &'a [toml::Value], hook_id: &str) -> Option<&'a toml::Value> {
    repos
        .iter()
        .find(|repo| repo.get("repo").and_then(toml::Value::as_str) == Some("local"))
        .and_then(|repo| repo.get("hooks"))
        .and_then(toml::Value::as_array)
        .and_then(|hooks| {
            hooks
                .iter()
                .find(|hook| hook.get("id").and_then(toml::Value::as_str) == Some(hook_id))
        })
}

fn package_rule_by_group<'a>(rules: &'a [Value], group_name: &str) -> &'a Value {
    rules
        .iter()
        .find(|rule| rule.get("groupName").and_then(Value::as_str) == Some(group_name))
        .unwrap()
}

fn custom_manager_by_file_pattern<'a>(managers: &'a [Value], file_pattern: &str) -> Vec<&'a Value> {
    managers
        .iter()
        .filter(|manager| {
            manager["managerFilePatterns"]
                .as_array()
                .is_some_and(|patterns| {
                    patterns
                        .iter()
                        .any(|pattern| pattern.as_str() == Some(file_pattern))
                })
        })
        .collect()
}

#[skuld::test]
fn claude_local_policy_file_is_present_and_trackable() {
    let claude_local = repo_root().join("CLAUDE.local.md");
    assert!(
        claude_local.exists(),
        "CLAUDE.local.md should be checked in"
    );

    let gitignore = read(".gitignore");
    assert!(
        !gitignore
            .lines()
            .any(|line| line.trim() == "CLAUDE.local.md"),
        ".gitignore still ignores CLAUDE.local.md",
    );

    let content = read("CLAUDE.local.md");
    assert!(content.contains("create a GitHub issue"));
    assert!(content.contains("separate git worktree"));
}

#[skuld::test]
fn prek_config_parses_and_preserves_hook_contracts() {
    let prek = parse_toml("prek.toml");
    let install_types = prek["default_install_hook_types"].as_array().unwrap();
    let install_types: Vec<_> = install_types
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        install_types,
        vec!["pre-commit".to_owned(), "commit-msg".to_owned()]
    );

    let repos = prek["repos"].as_array().unwrap();
    for hook_id in [
        "no-llm-author-test",
        "no-llm-author",
        "format-section-comments-test",
        "format-section-comments",
        "cargo-fmt",
        "cargo-clippy",
        "taplo-fmt",
    ] {
        assert!(
            local_hook_by_id(repos, hook_id).is_some(),
            "missing local hook {hook_id}",
        );
    }

    let commit_msg_hook = local_hook_by_id(repos, "no-llm-author").unwrap();
    let stages = commit_msg_hook["stages"].as_array().unwrap();
    let stages: Vec<_> = stages
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(stages, vec!["commit-msg".to_owned()]);

    let formatter_ids = [
        "cargo-fmt",
        "format-section-comments",
        "yapf",
        "mdformat",
        "prettier",
        "taplo-fmt",
    ];
    for hook_id in formatter_ids {
        assert!(
            repos.iter().any(|repo| {
                repo.get("hooks")
                    .and_then(toml::Value::as_array)
                    .is_some_and(|hooks| {
                        hooks.iter().any(|hook| {
                            hook.get("id").and_then(toml::Value::as_str) == Some(hook_id)
                        })
                    })
            }),
            "missing formatter hook {hook_id}",
        );
    }

    let prettier_hook = local_hook_by_id(repos, "prettier").unwrap();
    let prettier_files = prettier_hook["files"].as_str().unwrap();
    assert!(
        !prettier_files.contains("toml"),
        "prettier should not be responsible for TOML files",
    );
    assert_eq!(prettier_hook["entry"].as_str().unwrap(), "prettier --check");
    let prettier_deps = prettier_hook["additional_dependencies"].as_array().unwrap();
    assert_eq!(prettier_deps.len(), 1);
    assert_eq!(prettier_deps[0].as_str().unwrap(), "prettier@3.5.3");

    let taplo_hook = local_hook_by_id(repos, "taplo-fmt").unwrap();
    assert_eq!(taplo_hook["language"].as_str().unwrap(), "system");
    assert_eq!(taplo_hook["entry"].as_str().unwrap(), "taplo fmt --check");
    assert_eq!(taplo_hook["types"][0].as_str().unwrap(), "toml");

    let mdformat_repo = repos
        .iter()
        .find(|repo| {
            repo.get("repo").and_then(toml::Value::as_str)
                == Some("https://github.com/hukkin/mdformat")
        })
        .unwrap();
    let mdformat_hook = mdformat_repo["hooks"].as_array().unwrap();
    let mdformat_gfm_deps = mdformat_hook[0]["additional_dependencies"]
        .as_array()
        .unwrap();
    assert_eq!(
        mdformat_gfm_deps[0].as_str().unwrap(),
        "mdformat-gfm==1.0.0"
    );

    for hook_id in [
        "check-executables-have-shebangs",
        "check-shebang-scripts-are-executable",
        "mixed-line-ending",
        "editorconfig-checker",
        "actionlint",
    ] {
        assert!(
            repos.iter().any(|repo| {
                repo.get("hooks")
                    .and_then(toml::Value::as_array)
                    .is_some_and(|hooks| {
                        hooks.iter().any(|hook| {
                            hook.get("id").and_then(toml::Value::as_str) == Some(hook_id)
                        })
                    })
            }),
            "missing CI-critical external hook {hook_id}",
        );
    }
}

#[skuld::test]
fn renovate_config_parses_and_groups_updates_by_ecosystem() {
    let renovate = parse_json5(".github/renovate.json5");
    assert_eq!(renovate["minimumReleaseAge"], "7 days");
    assert_eq!(renovate["platformAutomerge"], true);

    let rules = renovate["packageRules"].as_array().unwrap();
    let github_actions_rule = package_rule_by_group(rules, "GitHub Actions");
    assert_eq!(
        github_actions_rule["matchManagers"][0].as_str().unwrap(),
        "github-actions"
    );

    let rust_rule = package_rule_by_group(rules, "Rust crates");
    assert!(rust_rule["matchManagers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|manager| manager.as_str() == Some("cargo")));

    let python_rule = package_rule_by_group(rules, "Python packages");
    assert_eq!(
        python_rule["matchManagers"][0].as_str().unwrap(),
        "custom.regex"
    );
    assert_eq!(python_rule["matchDepTypes"][0].as_str().unwrap(), "python");

    let npm_rule = package_rule_by_group(rules, "npm packages");
    assert_eq!(
        npm_rule["matchManagers"][0].as_str().unwrap(),
        "custom.regex"
    );
    assert_eq!(npm_rule["matchDepTypes"][0].as_str().unwrap(), "npm");

    let rust_tooling_rule = package_rule_by_group(rules, "Rust tooling");
    assert_eq!(
        rust_tooling_rule["matchManagers"][0].as_str().unwrap(),
        "custom.regex"
    );
    assert_eq!(
        rust_tooling_rule["matchDepTypes"][0].as_str().unwrap(),
        "rust"
    );

    let hook_rule = package_rule_by_group(rules, "Prek hooks");
    assert_eq!(
        hook_rule["matchManagers"][0].as_str().unwrap(),
        "custom.regex"
    );
    assert_eq!(
        hook_rule["matchDepTypes"][0].as_str().unwrap(),
        "pre-commit-hooks"
    );

    let custom_managers = renovate["customManagers"].as_array().unwrap();
    let prek_managers = custom_manager_by_file_pattern(custom_managers, "/^prek\\.toml$/");
    let ci_managers =
        custom_manager_by_file_pattern(custom_managers, "/^\\.github/workflows/ci\\.ya?ml$/");
    assert!(
        !prek_managers.is_empty(),
        "renovate should manage pinned versions inside prek.toml",
    );
    assert!(
        !ci_managers.is_empty(),
        "renovate should manage pinned tool versions inside CI workflows",
    );
    assert!(
        prek_managers.iter().any(|manager| {
            manager["datasourceTemplate"].as_str() == Some("github-tags")
                && manager["depTypeTemplate"].as_str() == Some("pre-commit-hooks")
                && manager["matchStrings"]
                    .as_array()
                    .is_some_and(|patterns| {
                        patterns.iter().any(|pattern| {
                            pattern.as_str()
                                == Some(
                                    "repo\\s*=\\s*\"https://github\\.com/(?<depName>[^\"]+)\"\\s*\\nrev\\s*=\\s*\"(?<currentValue>[^\"]+)\"",
                                )
                        })
                    })
        }),
        "renovate should extract GitHub hook revisions from prek.toml",
    );
    assert!(
        prek_managers.iter().any(|manager| {
            manager["datasourceTemplate"].as_str() == Some("pypi")
                && manager["depTypeTemplate"].as_str() == Some("python")
                && manager["versioningTemplate"].as_str() == Some("pep440")
                && manager["matchStrings"].as_array().is_some_and(|patterns| {
                    patterns.iter().any(|pattern| {
                        pattern.as_str()
                            == Some("(?<depName>[A-Za-z0-9._-]+)==(?<currentValue>[^\"]+)")
                    })
                })
        }),
        "renovate should extract Python hook dependencies from prek.toml",
    );
    assert!(
        prek_managers.iter().any(|manager| {
            manager["datasourceTemplate"].as_str() == Some("npm")
                && manager["depTypeTemplate"].as_str() == Some("npm")
                && manager["matchStrings"].as_array().is_some_and(|patterns| {
                    patterns.iter().any(|pattern| {
                        pattern.as_str() == Some("(?<depName>[^\"\\s]+)@(?<currentValue>[^\"]+)")
                    })
                })
        }),
        "renovate should extract npm hook dependencies from prek.toml",
    );
    assert!(
        ci_managers.iter().any(|manager| {
            manager["datasourceTemplate"].as_str() == Some("pypi")
                && manager["depTypeTemplate"].as_str() == Some("python")
                && manager["versioningTemplate"].as_str() == Some("pep440")
                && manager["matchStrings"].as_array().is_some_and(|patterns| {
                    patterns.iter().any(|pattern| {
                        pattern.as_str()
                            == Some("uv tool install \"(?<depName>prek)==(?<currentValue>[^\"]+)\"")
                    })
                })
        }),
        "renovate should extract the pinned prek version from ci.yaml",
    );
    assert!(
        ci_managers.iter().any(|manager| {
            manager["datasourceTemplate"].as_str() == Some("crate")
                && manager["depTypeTemplate"].as_str() == Some("rust")
                && manager["matchStrings"]
                    .as_array()
                    .is_some_and(|patterns| {
                        patterns.iter().any(|pattern| {
                            pattern.as_str()
                                == Some(
                                    "cargo install --locked (?<depName>taplo-cli) --version (?<currentValue>[^\\s]+)",
                                )
                        })
                    })
        }),
        "renovate should extract the pinned taplo version from ci.yaml",
    );

    let major_rule = rules.iter().find(|rule| {
        rule.get("matchUpdateTypes")
            .and_then(Value::as_array)
            .is_some_and(|types| types.iter().any(|ty| ty.as_str() == Some("major")))
    });
    let major_rule = major_rule.expect("missing major-update rule");
    assert!(major_rule.get("groupName").is_some_and(Value::is_null));
}

#[skuld::test]
fn ci_workflow_parses_and_covers_required_platforms() {
    let ci = parse_yaml(".github/workflows/ci.yaml");
    assert!(ci["on"].get("pull_request").is_some());
    assert_eq!(ci["on"]["push"]["branches"][0], "main");

    let jobs = ci["jobs"].as_object().unwrap();
    assert!(jobs.contains_key("lint"));
    assert!(jobs.contains_key("test"));
    assert_eq!(jobs["test"]["name"], "Test (${{ matrix.platform }})");

    let lint_steps = jobs["lint"]["steps"].as_array().unwrap();
    assert!(
        lint_steps.iter().any(|step| {
            step["name"].as_str() == Some("Install taplo")
                && step["run"].as_str().is_some_and(|run| {
                    run.contains("cargo install --locked taplo-cli --version 0.10.0")
                })
        }),
        "lint job should install taplo before running prek",
    );
    assert!(
        lint_steps.iter().any(|step| {
            step["name"].as_str() == Some("Run linters")
                && step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains("prek run --all-files"))
        }),
        "lint job should run prek against all files",
    );

    let include = jobs["test"]["strategy"]["matrix"]["include"]
        .as_array()
        .unwrap();
    let platforms: BTreeMap<_, _> = include
        .iter()
        .map(|entry| {
            (
                entry["platform"].as_str().unwrap().to_owned(),
                entry["runner"].as_str().unwrap().to_owned(),
            )
        })
        .collect();

    assert_eq!(platforms.get("windows/amd64").unwrap(), "windows-latest");
    assert_eq!(platforms.get("linux/amd64").unwrap(), "ubuntu-latest");
    assert_eq!(platforms.get("linux/arm64").unwrap(), "ubuntu-24.04-arm");
    assert_eq!(platforms.get("darwin/arm64").unwrap(), "macos-latest");
    let test_steps = jobs["test"]["steps"].as_array().unwrap();
    assert!(
        test_steps.iter().any(|step| {
            step["name"].as_str() == Some("Run tests")
                && step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains("cargo test --locked"))
        }),
        "test job should run cargo test with --locked",
    );
}

#[skuld::test]
fn legacy_pre_commit_config_is_removed() {
    assert!(
        !repo_root().join(".pre-commit-config.yaml").exists(),
        ".pre-commit-config.yaml should be removed after migrating to prek.toml",
    );
}

#[skuld::test]
fn docs_describe_the_repo_local_workflow_correctly() {
    let readme = read("README.md");
    assert!(readme.contains("prek run --all-files"));
    assert!(readme.contains("git add ."));
    assert!(readme.contains("pre-tool hook"));

    let claude = read("CLAUDE.md");
    assert!(claude.lines().any(|line| {
        line
            == "| `src/filter/bash.rs`         | `BashFilter { items: Vec<BashFilterItem> }` — item-based command filter. Items: `Arg0(Name \\| Path)`, `Arg(String)`, `MatchOne`, `MatchZeroOrMore`. `matches(raw_arg0, args, cwd)` walks items with backtracking for `MatchZeroOrMore`.                                                                                                                                        |"
    }));
}
