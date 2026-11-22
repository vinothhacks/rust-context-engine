//! Single-pass transformation ledger and coexistence markers (ADR 0004).

use serde::{Deserialize, Serialize};

use crate::scope::ArtifactId;

/// Versioned pre-normalization transform that strips ANSI CSI/OSC sequences on derived views.
pub const TRANSFORM_STRIP_ANSI_V1: &str = "strip_ansi@1";
/// Versioned pre-index / pre-view secret redaction transform.
pub const TRANSFORM_SECRET_REDACT_V1: &str = "secret_redact@1";
/// Versioned Cargo test output reducer.
pub const TRANSFORM_CARGO_TEST_V1: &str = "cargo_test@1";
/// Versioned pytest / Jest / Vitest output reducer.
pub const TRANSFORM_PYTEST_JEST_V1: &str = "pytest_jest@1";
/// Versioned compiler diagnostic (`rustc` / `cargo check` / `tsc`) reducer.
pub const TRANSFORM_COMPILER_DIAG_V1: &str = "compiler_diag@1";
/// Versioned Git (`status` / `diff` / `log`) reducer.
pub const TRANSFORM_GIT_REDUCER_V1: &str = "git_reducer@1";
/// Versioned structured JSON reducer.
pub const TRANSFORM_STRUCTURED_JSON_V1: &str = "structured_json@1";
/// Versioned log template deduplication reducer.
pub const TRANSFORM_LOG_DEDUP_V1: &str = "log_dedup@1";
/// Versioned lexical search (`rg` / `grep`) hit grouper.
pub const TRANSFORM_SEARCH_HITS_V1: &str = "search_hits@1";
/// Versioned safe bounded fallback reducer for unknown or binary streams.
pub const TRANSFORM_UNKNOWN_SAFE_V1: &str = "unknown_safe@1";

/// Prefix emitted in text banners so CLI wrappers and host hooks detect already-reduced payloads.
pub const LEDGER_HEADER_PREFIX: &str = "[context-engine:v1 ";

const NON_DOMAIN_PREPROCESSORS: &[&str] = &[TRANSFORM_STRIP_ANSI_V1, TRANSFORM_SECRET_REDACT_V1];

/// Ordered, deduplicated ledger of transformations applied to derive an `ArtifactView`.
///
/// Enforces the ADR 0004 single-pass domain-reduction invariant so outputs are never
/// double-compressed across MCP, CLI, or opt-in agent hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransformationLedger {
    entries: Vec<String>,
}

impl TransformationLedger {
    /// Creates an empty transformation ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Constructs a ledger from an existing iterator of step identifiers, deduplicating in order.
    pub fn from_entries<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut ledger = Self::new();
        for item in iter {
            ledger.record(item);
        }
        ledger
    }

    /// Appends `step` if not already recorded. Returns `true` if newly added.
    pub fn record(&mut self, step: impl Into<String>) -> bool {
        let step = step.into();
        if self.entries.iter().any(|existing| existing == &step) {
            return false;
        }
        self.entries.push(step);
        true
    }

    /// Attempts to record a domain reducer, returning `false` without mutating if a domain
    /// reducer has already been recorded on this ledger.
    pub fn record_domain_reducer(&mut self, reducer_id: impl Into<String>) -> bool {
        if self.has_domain_reducer() {
            return false;
        }
        self.record(reducer_id)
    }

    /// Returns `true` if `step` is present in the ledger.
    #[must_use]
    pub fn contains(&self, step: &str) -> bool {
        self.entries.iter().any(|existing| existing == step)
    }

    /// Returns `true` if any domain reducer (beyond `strip_ansi@1` / `secret_redact@1`) has run.
    #[must_use]
    pub fn has_domain_reducer(&self) -> bool {
        self.entries
            .iter()
            .any(|step| !NON_DOMAIN_PREPROCESSORS.contains(&step.as_str()))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.entries
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.entries
    }

    /// Formats a deterministic single-line provenance header for text-mode outputs and hooks.
    #[must_use]
    pub fn format_banner(artifact_id: &ArtifactId, transforms: &[String]) -> String {
        let joined = if transforms.is_empty() {
            "none".to_string()
        } else {
            transforms.join(",")
        };
        format!(
            "{LEDGER_HEADER_PREFIX}artifact={} transforms={joined}]",
            artifact_id.as_str()
        )
    }

    /// Inspects an arbitrary text payload and returns `true` if it already carries a
    /// `context-engine` v1 banner or serialized `ArtifactEnvelope` transformation marker.
    #[must_use]
    pub fn is_already_reduced_payload(payload: &str) -> bool {
        let trimmed = payload.trim_start();
        if trimmed.starts_with(LEDGER_HEADER_PREFIX) {
            return true;
        }
        if trimmed.starts_with('{')
            && trimmed.contains("\"schema_version\"")
            && trimmed.contains("\"artifact_id\"")
            && trimmed.contains("\"transformations\"")
        {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if val.get("schema_version").and_then(serde_json::Value::as_u64) == Some(1)
                    && val
                        .get("artifact_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|id| id.starts_with("a_"))
                    && val
                        .pointer("/view/transformations")
                        .and_then(serde_json::Value::as_array)
                        .is_some()
                {
                    return true;
                }
            }
        }
        false
    }
}
