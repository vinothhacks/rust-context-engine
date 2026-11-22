//! Scoped artifact manifest schema and domain-separated scope-binding verification.

use context_core::{
    ArtifactEnvelope, ArtifactId, ArtifactSource, ArtifactView, SessionId, StreamEncoding,
    StreamKind, WorkspaceScopeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current on-disk manifest schema version (`1`).
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Raw stream input supplied to `BlobStore::put_artifact_streams`.
#[derive(Debug, Clone)]
pub struct ArtifactStreamInput<'a> {
    /// Which logical stream this byte slice belongs to (`Stdout`, `Stderr`, or `Document`).
    pub stream: StreamKind,
    /// Captured bytes (bounded by `context-capture`).
    pub bytes: &'a [u8],
    /// Whether the stream was truncated during capture.
    pub truncated: bool,
}

impl<'a> ArtifactStreamInput<'a> {
    /// Constructs an [`ArtifactStreamInput`] for `stream` and `bytes`.
    #[must_use]
    pub const fn new(stream: StreamKind, bytes: &'a [u8], truncated: bool) -> Self {
        Self {
            stream,
            bytes,
            truncated,
        }
    }
}

/// Request parameters for persisting a multi-stream command or single-stream document artifact.
#[derive(Debug, Clone)]
pub struct PutArtifactRequest<'a> {
    /// Optional pre-minted `ArtifactId`; when `None`, `BlobStore` mints one deterministically.
    pub artifact_id: Option<ArtifactId>,
    /// Command or document provenance metadata.
    pub source: ArtifactSource,
    /// Captured streams (`Stdout` + `Stderr`, or `Document`).
    pub streams: Vec<ArtifactStreamInput<'a>>,
    /// Whether overall capture completed without timeout/cancellation (`true` for normal runs).
    pub capture_complete: bool,
    /// Optional pre-computed compact `ArtifactView`; if `None`, a safe placeholder view is stored
    /// and can be updated via `BlobStore::update_artifact_view`.
    pub view: Option<ArtifactView>,
}

/// Per-stream persistence metadata recorded inside [`StoredArtifactManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStreamRef {
    pub stream: StreamKind,
    /// SHA-256 of the raw captured bytes prior to any redaction.
    pub raw_sha256: String,
    /// Byte count of the raw captured bytes.
    pub raw_bytes: u64,
    /// SHA-256 of the `.zst` blob's uncompressed payload (`None` when quarantined or empty-unavailable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_sha256: Option<String>,
    /// Uncompressed byte count of the stored blob.
    pub stored_bytes: u64,
    /// On-disk compressed `.zst` byte count.
    pub compressed_bytes: u64,
    /// Detected encoding of the stored payload.
    pub encoding: StreamEncoding,
    /// Whether `context-capture` truncated trailing bytes on this stream.
    pub truncated: bool,
    /// `true` when `stored_sha256` equals untouched `raw_sha256`.
    pub exact_raw_preserved: bool,
    /// `true` when `context_get` is permitted to serve this stream.
    pub originals_available: bool,
    /// `true` when `SecretGuard` quarantined this stream.
    pub quarantined: bool,
    /// Number of secret findings redacted in this stream.
    pub secrets_redacted: usize,
    /// Distinct triggered `SecretRuleKind` IDs in this stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_rule_ids: Vec<String>,
}

/// Authoritative scoped manifest stored at `.context-engine/store/manifests/<artifact_id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredArtifactManifest {
    pub manifest_version: u32,
    pub artifact_id: ArtifactId,
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
    /// Domain-separated SHA-256 commitment binding scope, session, artifact ID, and stream hashes.
    pub scope_binding_sha256: String,
    /// Creation timestamp in Unix epoch milliseconds (used for TTL expiry).
    pub created_at_unix_ms: u64,
    /// Last read/write timestamp in Unix epoch milliseconds (used for LRU quota eviction).
    pub last_accessed_unix_ms: u64,
    /// Full v1 `ArtifactEnvelope`.
    pub envelope: ArtifactEnvelope,
    /// Stored stream descriptors (`Stdout`/`Stderr` or `Document`).
    pub streams: Vec<StoredStreamRef>,
}

/// Computes a deterministic domain-separated SHA-256 commitment over `(workspace_scope_id,
/// session_id, artifact_id, streams)` so tampered or transplanted manifests are rejected.
#[must_use]
pub fn compute_scope_binding_sha256(
    workspace_scope_id: &WorkspaceScopeId,
    session_id: &SessionId,
    artifact_id: &ArtifactId,
    streams: &[StoredStreamRef],
) -> String {
    let mut hasher = Sha256::new();
    update_lp(&mut hasher, b"context-engine:manifest-binding:v1");
    update_lp(&mut hasher, workspace_scope_id.as_str().as_bytes());
    update_lp(&mut hasher, session_id.as_str().as_bytes());
    update_lp(&mut hasher, artifact_id.as_str().as_bytes());
    hasher.update((streams.len() as u64).to_le_bytes());

    for s in streams {
        update_lp(&mut hasher, s.stream.as_str().as_bytes());
        update_lp(&mut hasher, s.raw_sha256.as_bytes());
        update_lp(
            &mut hasher,
            s.stored_sha256.as_deref().unwrap_or("<none>").as_bytes(),
        );
        hasher.update([
            u8::from(s.exact_raw_preserved),
            u8::from(s.originals_available),
            u8::from(s.quarantined),
        ]);
    }

    hex::encode(hasher.finalize())
}

fn update_lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
