//! Output reduction, capture, retrieval, and storage budget contracts.

use serde::{Deserialize, Serialize};

use crate::error::{ContextError, Result};

/// Configurable byte, line, and retention budgets governing capture, reduction, search, and retrieval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionBudget {
    /// Maximum UTF-8 byte length of `ArtifactView::safe_excerpt` returned immediately to an agent.
    pub max_view_bytes: usize,
    /// Maximum line count of `ArtifactView::safe_excerpt`.
    pub max_view_lines: usize,
    /// Maximum distinct failure items (failing tests / compiler errors) listed inline before elision.
    pub max_failure_items: usize,
    /// Maximum causal stack/assertion trace lines kept per failure item.
    pub max_trace_lines_per_failure: usize,
    /// Maximum UTF-8 preview bytes emitted by `unknown_safe@1` fallback views.
    pub max_preview_bytes: usize,
    /// Hard maximum bytes returned by a single `context_get` call.
    pub max_get_bytes: usize,
    /// Hard maximum lines returned by a single `context_get` line-range call.
    pub max_get_lines: usize,
    /// Maximum ranked hits returned by a single `context_search` call.
    pub max_search_results: usize,
    /// Maximum UTF-8 bytes per individual `context_search` snippet.
    pub max_search_snippet_bytes: usize,
    /// Maximum captured bytes per output stream (`stdout` / `stderr`) before truncation.
    pub max_capture_stream_bytes: u64,
    /// Per-workspace blob store quota in bytes before pruning is required.
    pub max_workspace_store_bytes: u64,
    /// Artifact retention time-to-live in seconds.
    pub retention_ttl_secs: u64,
}

impl Default for ReductionBudget {
    fn default() -> Self {
        Self {
            max_view_bytes: 4_096,
            max_view_lines: 80,
            max_failure_items: 25,
            max_trace_lines_per_failure: 12,
            max_preview_bytes: 1_024,
            max_get_bytes: 32_768,
            max_get_lines: 200,
            max_search_results: 20,
            max_search_snippet_bytes: 512,
            max_capture_stream_bytes: 16 * 1024 * 1024,
            max_workspace_store_bytes: 512 * 1024 * 1024,
            retention_ttl_secs: 14 * 24 * 3_600,
        }
    }
}

impl ReductionBudget {
    /// Validates that all budget parameters are non-zero and internally consistent.
    pub fn validate(&self) -> Result<()> {
        if self.max_view_bytes == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_view_bytes",
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.max_view_lines == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_view_lines",
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.max_preview_bytes == 0 || self.max_preview_bytes > self.max_view_bytes {
            return Err(ContextError::InvalidConfig {
                field: "max_preview_bytes",
                reason: "must be in 1..=max_view_bytes".to_string(),
            });
        }
        if self.max_get_bytes == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_get_bytes",
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.max_get_lines == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_get_lines",
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.max_capture_stream_bytes == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_capture_stream_bytes",
                reason: "must be greater than 0".to_string(),
            });
        }
        Ok(())
    }

    /// Truncates `text` to at most `max_bytes` on a valid UTF-8 codepoint boundary.
    ///
    /// Returns `(slice, was_truncated)`.
    #[must_use]
    pub fn truncate_utf8_safe<'a>(&self, text: &'a str, max_bytes: usize) -> (&'a str, bool) {
        truncate_str_utf8_boundary(text, max_bytes)
    }

    /// Truncates `text` to fit within both `self.max_view_lines` and `self.max_view_bytes`
    /// without splitting multi-byte UTF-8 characters.
    ///
    /// Returns `(bounded_string, was_truncated)`.
    #[must_use]
    pub fn bound_view_excerpt(&self, text: &str) -> (String, bool) {
        let mut out = String::new();
        let mut truncated = false;

        for (idx, line) in text.lines().enumerate() {
            if idx >= self.max_view_lines {
                truncated = true;
                break;
            }
            if idx > 0 {
                if out.len() + 1 > self.max_view_bytes {
                    truncated = true;
                    break;
                }
                out.push('\n');
            }
            let remaining = self.max_view_bytes.saturating_sub(out.len());
            let (slice, line_cut) = truncate_str_utf8_boundary(line, remaining);
            out.push_str(slice);
            if line_cut {
                truncated = true;
                break;
            }
        }

        (out, truncated)
    }
}

/// Truncates `text` to at most `max_bytes` on a valid UTF-8 character boundary.
#[must_use]
pub fn truncate_str_utf8_boundary(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// Deterministic heuristic token estimate (`ceil(bytes / 4)`) used consistently across telemetry.
#[must_use]
pub const fn estimate_tokens_from_bytes(bytes: u64) -> u64 {
    if bytes == 0 {
        0
    } else {
        bytes.div_ceil(4)
    }
}

/// Deterministic heuristic token estimate for a UTF-8 string.
#[must_use]
pub fn estimate_tokens_from_str(text: &str) -> u64 {
    estimate_tokens_from_bytes(text.len() as u64)
}
