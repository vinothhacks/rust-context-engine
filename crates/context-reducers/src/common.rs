//! Shared internal helpers for deterministic reducers: recovery pointers, insertion-ordered
//! deduplication, and exit-status formatting.

use std::collections::HashSet;

use context_core::{ArtifactId, StreamKind, ViewKind};

/// Output produced by an individual domain reducer before final `SecretGuard` and budget enforcement.
#[derive(Debug, Clone)]
pub(crate) struct DomainReduction {
    pub kind: ViewKind,
    pub safe_excerpt: String,
    pub omitted: bool,
    pub failure_identifiers: Vec<String>,
}

/// Range selector advertised in a `context_get` recovery hint.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RecoveryRange {
    Lines { start: usize, end: usize },
    Bytes { start: u64, end: u64 },
}

/// Formats a deterministic `context_get` recovery hint.
#[must_use]
pub(crate) fn format_recovery_hint(
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    stream: StreamKind,
    range: RecoveryRange,
) -> String {
    if !originals_available {
        return "recovery: unavailable (raw stream withheld by secret policy)".to_string();
    }

    let id_part = match artifact_id {
        Some(id) => format!(" {}", id.as_str()),
        None => String::new(),
    };
    let range_part = match range {
        RecoveryRange::Lines { start, end } => {
            let s = start.max(1);
            let e = end.max(s);
            format!("--lines {s}:{e}")
        }
        RecoveryRange::Bytes { start, end } => {
            let e = end.max(start);
            format!("--bytes {start}:{e}")
        }
    };

    format!(
        "recover: context_get{id_part} --stream {} {range_part}",
        stream.as_str()
    )
}

/// Deduplicates strings while preserving exact first-seen causal order.
#[must_use]
pub(crate) fn dedup_preserve_order(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Formats an optional process exit code + timeout status cleanly.
#[must_use]
pub(crate) fn format_exit_badge(exit_code: Option<i32>, timed_out: bool) -> String {
    match (exit_code, timed_out) {
        (Some(code), true) => format!("exit {code}, TIMED_OUT"),
        (None, true) => "exit none, TIMED_OUT".to_string(),
        (Some(code), false) => format!("exit {code}"),
        (None, false) => "exit unknown".to_string(),
    }
}

/// Counts non-empty lines or total `\n`-delimited lines consistently (`0` for empty `""`).
#[must_use]
pub(crate) fn count_lines(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        text.lines().count()
    }
}
