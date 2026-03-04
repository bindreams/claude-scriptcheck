use path_clean::PathClean;
use std::path::PathBuf;

/// Returns true if the path segment contains glob wildcard characters.
pub fn is_wildcard_segment(segment: &str) -> bool {
    segment.contains('*') || segment.contains('?') || segment.contains('[') || segment.contains('{')
}

/// Best-effort path canonicalization.
///
/// 1. Logically normalizes the path (resolves `.` and `..`, deduplicates `/`).
/// 2. Splits at the first wildcard segment (containing `*`, `?`, `[`, or `{`).
/// 3. Filesystem-canonicalizes the prefix by walking backwards to find the
///    deepest existing ancestor (resolves symlinks).
/// 4. Reassembles: canonical prefix + unresolved segments + wildcard tail.
///
/// Falls back to the logically normalized path if filesystem canonicalization
/// fails entirely.
pub fn best_effort_canonicalize(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // Step 1: Logical normalization
    let normalized = PathBuf::from(path).clean();
    let normalized_str = normalized.to_string_lossy().to_string();

    // Step 2: Split at first wildcard segment
    let segments: Vec<&str> = normalized_str.split('/').collect();
    let wildcard_idx = segments
        .iter()
        .position(|s| is_wildcard_segment(s))
        .unwrap_or(segments.len());

    // Nothing to canonicalize if the first segment is already a wildcard
    // (for absolute paths, first segment is "" so wildcard_idx >= 2 if any real segment is wildcard)
    let prefix_segments = &segments[..wildcard_idx];
    let suffix_segments = &segments[wildcard_idx..];

    if prefix_segments.is_empty()
        || (prefix_segments.len() == 1 && prefix_segments[0].is_empty())
    {
        return normalized_str;
    }

    // Step 3: Walk backwards from the prefix to find deepest existing ancestor
    let mut probe = PathBuf::from(prefix_segments.join("/"));
    // For absolute paths, the join of ["", "home", "user"] gives "/home/user" — correct
    let mut tail_parts: Vec<String> = Vec::new();

    loop {
        match std::fs::canonicalize(&probe) {
            Ok(canonical) => {
                let mut result = canonical.to_string_lossy().to_string();

                // Append unresolved prefix segments (collected in reverse order)
                for part in tail_parts.iter().rev() {
                    result.push('/');
                    result.push_str(part);
                }

                // Append wildcard suffix
                for seg in suffix_segments {
                    result.push('/');
                    result.push_str(seg);
                }

                return result;
            }
            Err(_) => match probe.file_name() {
                Some(name) => {
                    tail_parts.push(name.to_string_lossy().to_string());
                    probe.pop();
                }
                None => break, // at root or empty
            },
        }
    }

    // Step 4: Fallback — return logically normalized path
    normalized_str
}
