//! Bounded workspace file and in-memory document ingestion (`capture_file`, `capture_bytes`).

use std::path::Path;

use context_core::{
    now_rfc3339_utc, ArtifactSource, BoundScope, CaptureSummary, ContextError, Result,
    StreamEncoding,
};
use context_execution::ExecutionGate;
use serde::{Deserialize, Serialize};

use crate::stream::{read_stream_bounded, CapturedStream, StreamAccumulator};

/// Captured document or workspace file ready for `SecretGuard`, persistence, and indexing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedDocument {
    /// Workspace-relative file path (`None` for inline supplied bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_relative: Option<String>,
    /// Optional caller-supplied label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional or inferred MIME media type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Bounded raw byte stream with SHA-256 and detected [`StreamEncoding`].
    pub stream: CapturedStream,
    /// RFC 3339 UTC timestamp recorded at ingestion time.
    pub captured_at: String,
}

impl CapturedDocument {
    /// Returns `true` if the document was captured completely without truncation or read error.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.stream.truncated && self.stream.read_error.is_none()
    }

    /// Converts provenance metadata into [`ArtifactSource::Document`].
    #[must_use]
    pub fn to_artifact_source(&self) -> ArtifactSource {
        ArtifactSource::Document {
            path_relative: self.path_relative.clone(),
            label: self.label.clone(),
            media_type: self.media_type.clone(),
            captured_at: self.captured_at.clone(),
        }
    }

    /// Builds a preliminary [`CaptureSummary`] for this document.
    #[must_use]
    pub fn to_capture_summary(&self, originals_available: bool) -> CaptureSummary {
        CaptureSummary::for_document(
            self.stream.sha256.clone(),
            self.stream.captured_len(),
            self.is_complete(),
            self.stream.encoding,
            originals_available,
        )
    }
}

/// Reads bounded bytes from a confined workspace file with TOCTOU verification and
/// [`StreamEncoding::detect`].
pub async fn capture_file(
    scope: &BoundScope,
    gate: &ExecutionGate,
    requested_path: &Path,
    max_bytes: u64,
) -> Result<CapturedDocument> {
    if max_bytes == 0 {
        return Err(ContextError::InvalidConfig {
            field: "max_bytes",
            reason: "max_bytes must be greater than 0".to_string(),
        });
    }

    let (file, confined) = gate.open_file(scope, requested_path).await?;
    let mut acc = StreamAccumulator::new(max_bytes);
    read_stream_bounded(file, &mut acc).await;

    if let Some(err_msg) = &acc.finalize_error_peek() {
        return Err(ContextError::Io(std::io::Error::other(err_msg.clone())));
    }

    let stream = acc.finalize();
    let media_type =
        Some(infer_media_type(Path::new(&confined.relative), stream.encoding).to_string());

    Ok(CapturedDocument {
        path_relative: Some(confined.relative),
        label: None,
        media_type,
        stream,
        captured_at: now_rfc3339_utc(),
    })
}

/// Captures an in-memory byte slice bounded to `max_bytes` with SHA-256 and [`StreamEncoding::detect`].
pub fn capture_bytes(
    bytes: &[u8],
    label: Option<String>,
    media_type: Option<String>,
    max_bytes: u64,
) -> Result<CapturedDocument> {
    if max_bytes == 0 {
        return Err(ContextError::InvalidConfig {
            field: "max_bytes",
            reason: "max_bytes must be greater than 0".to_string(),
        });
    }

    let stream = CapturedStream::from_slice_bounded(bytes, max_bytes);
    let resolved_media = media_type.or_else(|| {
        Some(
            match stream.encoding {
                StreamEncoding::Utf8 | StreamEncoding::Utf8Lossy => "text/plain",
                StreamEncoding::Binary => "application/octet-stream",
            }
            .to_string(),
        )
    });

    Ok(CapturedDocument {
        path_relative: None,
        label,
        media_type: resolved_media,
        stream,
        captured_at: now_rfc3339_utc(),
    })
}

impl StreamAccumulator {
    pub(crate) fn finalize_error_peek(&self) -> Option<String> {
        self.peek_read_error().map(str::to_string)
    }
}

fn infer_media_type(path: &Path, encoding: StreamEncoding) -> &'static str {
    if encoding == StreamEncoding::Binary {
        return "application/octet-stream";
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("rs") => "text/x-rust",
        Some("toml") => "application/toml",
        Some("json" | "jsonl") => "application/json",
        Some("md" | "markdown") => "text/markdown",
        Some("py") => "text/x-python",
        Some("ts" | "tsx") => "text/typescript",
        Some("js" | "jsx" | "mjs" | "cjs") => "text/javascript",
        Some("yml" | "yaml") => "application/yaml",
        Some("log" | "txt") => "text/plain",
        _ => "text/plain",
    }
}
