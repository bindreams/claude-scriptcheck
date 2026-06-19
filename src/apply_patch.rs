use crate::file_access::{AccessKind, FileAccess};
use crate::path_util;

pub fn extract_file_accesses(command: &str, cwd: &str) -> Result<Vec<FileAccess>, String> {
    let mut accesses = Vec::new();
    let mut pending_update_source: Option<String> = None;

    for line in command.lines() {
        if let Some(path) = line.strip_prefix("*** Add File: ") {
            accesses.push(write_access(path, cwd)?);
            pending_update_source = None;
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Delete File: ") {
            accesses.push(write_access(path, cwd)?);
            pending_update_source = None;
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            let resolved = resolve_patch_path(path, cwd)?;
            accesses.push(FileAccess {
                path: resolved.clone(),
                kind: AccessKind::Write,
            });
            pending_update_source = Some(resolved);
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Move to: ") {
            let target = write_access(path, cwd)?;
            if let Some(source) = pending_update_source.take() {
                accesses.push(FileAccess {
                    path: source,
                    kind: AccessKind::Write,
                });
            }
            accesses.push(target);
        }
    }

    if accesses.is_empty() {
        return Err("apply_patch command did not reference any files".into());
    }

    accesses.sort_by(|a, b| a.path.cmp(&b.path));
    accesses.dedup_by(|a, b| a.path == b.path && a.kind == b.kind);
    Ok(accesses)
}

fn write_access(path: &str, cwd: &str) -> Result<FileAccess, String> {
    Ok(FileAccess {
        path: resolve_patch_path(path, cwd)?,
        kind: AccessKind::Write,
    })
}

fn resolve_patch_path(path: &str, cwd: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("apply_patch referenced an empty path".into());
    }
    let normalized = path_util::normalize_separators(trimmed);
    Ok(crate::file_access::resolve_path(&normalized, cwd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_file_extracts_write() {
        let accesses = extract_file_accesses(
            "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-old\n+new\n*** End Patch\n",
            "/repo",
        )
        .unwrap();
        assert_eq!(
            accesses,
            vec![FileAccess {
                path: "/repo/src/main.rs".into(),
                kind: AccessKind::Write,
            }]
        );
    }

    #[test]
    fn move_to_emits_source_and_target_writes() {
        let accesses = extract_file_accesses(
            "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n@@\n-old\n+new\n*** End Patch\n",
            "/repo",
        )
        .unwrap();
        assert_eq!(
            accesses,
            vec![
                FileAccess {
                    path: "/repo/new.txt".into(),
                    kind: AccessKind::Write,
                },
                FileAccess {
                    path: "/repo/old.txt".into(),
                    kind: AccessKind::Write,
                },
            ]
        );
    }

    #[test]
    fn empty_patch_is_error() {
        let err = extract_file_accesses("*** Begin Patch\n*** End Patch\n", "/repo").unwrap_err();
        assert!(err.contains("did not reference any files"));
    }
}
