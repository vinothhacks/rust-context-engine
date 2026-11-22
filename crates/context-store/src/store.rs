//! Crash-safe content-addressed `zstd` blob store, scoped manifest verification,
//! bounded byte/line recovery, and TTL + LRU quota pruning.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use chrono::Utc;
use context_core::{
    sha256_hex, truncate_str_utf8_boundary, ArtifactEnvelope, ArtifactId, ArtifactSource,
    ArtifactView, BoundScope, ByteRange, CaptureSummary, ContextError, LineRange, RecoveryHandle,
    ReductionBudget, Result, SecretFinding, SecretGuard, SecretPolicyMode, StreamEncoding,
    StreamKind, ViewKind, EMPTY_SHA256_HEX, TRANSFORM_SECRET_REDACT_V1, TRANSFORM_UNKNOWN_SAFE_V1,
};
use serde::{Deserialize, Serialize};
use tempfile::Builder as TempBuilder;

use crate::manifest::{
    compute_scope_binding_sha256, ArtifactStreamInput, PutArtifactRequest, StoredArtifactManifest,
    StoredStreamRef, MANIFEST_SCHEMA_VERSION,
};
use crate::permissions::{
    apply_private_dir_permissions, apply_private_file_permissions, verify_directory_permissions,
    StorePermissionReport,
};

const DEFAULT_ZSTD_LEVEL: i32 = 3;
const ACL_SENTINEL_FILE: &str = ".acl_v1";

/// Outcome of protecting and optionally persisting a single raw byte slice via [`BlobStore::put_blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedBlobOutcome {
    /// SHA-256 of the input `raw_bytes` prior to any redaction.
    pub raw_sha256: String,
    /// Byte length of the input `raw_bytes`.
    pub raw_bytes: u64,
    /// SHA-256 of the uncompressed payload stored in `blobs/<2-hex>/<sha256>.zst` (`None` when quarantined).
    pub stored_sha256: Option<String>,
    /// Uncompressed byte length of the stored blob.
    pub stored_bytes: u64,
    /// Compressed `.zst` byte size on disk.
    pub compressed_bytes: u64,
    /// Detected encoding of the stored payload (`utf-8` or `binary`).
    pub encoding: StreamEncoding,
    /// Sanitized UTF-8 text safe for compact views and SQLite FTS5 indexing (`None` for binary).
    pub sanitized_index_text: Option<String>,
    /// Non-sensitive secret findings detected by `SecretGuard`.
    pub findings: Vec<SecretFinding>,
    /// `true` if `stored_sha256` equals `raw_sha256` without any modification.
    pub exact_raw_preserved: bool,
    /// `true` if `context_get` may serve content from this blob.
    pub originals_available: bool,
    /// `true` if quarantined under `SecretPolicyMode::Quarantine`.
    pub quarantined: bool,
}

/// Outcome of persisting an artifact's streams and scoped manifest via [`BlobStore::put_artifact_streams`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactOutcome {
    /// Persisted scoped manifest.
    pub manifest: StoredArtifactManifest,
    /// Validated v1 `ArtifactEnvelope`.
    pub envelope: ArtifactEnvelope,
    /// Sanitized UTF-8 text per stream ready for `context-reducers` and `context-search` FTS5.
    pub sanitized_streams: Vec<(StreamKind, Option<String>)>,
}

/// Paginated byte-range recovery payload returned by [`BlobStore::get_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSlicePage {
    pub artifact_id: ArtifactId,
    pub stream: StreamKind,
    /// Verified SHA-256 of the underlying stored stream.
    pub sha256: String,
    pub encoding: StreamEncoding,
    pub exact_raw_preserved: bool,
    /// Total uncompressed byte length of the stored stream.
    pub total_bytes: u64,
    /// Total line count when the stream is valid UTF-8 (`None` for binary streams).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<usize>,
    /// Clamped half-open byte range `[start, end)` actually returned.
    pub returned_range: ByteRange,
    /// `true` if `returned_range.end < total_bytes`.
    pub has_more: bool,
    /// Exact raw byte slice for `returned_range`.
    pub bytes: Vec<u8>,
}

impl ByteSlicePage {
    /// Attempts zero-copy UTF-8 borrowing of `self.bytes`.
    pub fn as_utf8(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.bytes)
    }

    /// Returns a lossy UTF-8 string view of `self.bytes`.
    #[must_use]
    pub fn to_utf8_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    /// Encodes `self.bytes` as standard Base64 for binary-safe JSON transport.
    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.bytes)
    }
}

/// Single 1-indexed line entry inside [`LineSlicePage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedLine {
    pub line_number: usize,
    pub content: String,
}

/// Paginated 1-indexed inclusive line-range recovery payload returned by [`BlobStore::get_lines`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineSlicePage {
    pub artifact_id: ArtifactId,
    pub stream: StreamKind,
    /// Verified SHA-256 of the underlying stored stream.
    pub sha256: String,
    /// `utf-8` when the stored stream is valid UTF-8, or `utf-8-lossy` when derived from binary/non-UTF-8.
    pub encoding: StreamEncoding,
    pub exact_raw_preserved: bool,
    /// Total uncompressed byte length of the stored stream.
    pub total_bytes: u64,
    /// Total number of derived lines in the stream.
    pub total_lines: usize,
    /// Clamped 1-indexed inclusive `[start_line, end_line]` returned (`None` if stream has 0 lines or start > total_lines).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned_range: Option<LineRange>,
    /// `true` if additional lines (or truncated bytes on the last line) remain after `returned_range`.
    pub has_more: bool,
    /// `true` if output was capped early to stay within `ReductionBudget::max_get_bytes`.
    pub byte_budget_truncated: bool,
    /// Numbered lines in `returned_range`.
    pub lines: Vec<IndexedLine>,
    /// Newline-joined text of `lines`.
    pub text: String,
}

/// Retention parameters passed to [`BlobStore::prune`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunePolicy {
    /// Optional TTL in seconds (`None` disables age-based expiry).
    pub ttl_secs: Option<u64>,
    /// Optional workspace store byte ceiling (`None` disables size-based LRU eviction).
    pub max_store_bytes: Option<u64>,
    /// Optional reference clock override in Unix epoch milliseconds (`None` uses current wall clock).
    pub now_unix_ms: Option<u64>,
}

/// Summary of artifacts and blobs reclaimed by [`BlobStore::prune`] / [`BlobStore::enforce_quota_and_ttl`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PruneReport {
    pub expired_artifacts: usize,
    pub quota_evicted_artifacts: usize,
    pub removed_manifests: usize,
    pub removed_blobs: usize,
    pub removed_temp_files: usize,
    pub freed_bytes: u64,
    pub remaining_artifacts: usize,
    pub remaining_blobs: usize,
    pub remaining_bytes: u64,
    pub evicted_artifact_ids: Vec<ArtifactId>,
}

/// Current storage footprint metrics reported by [`BlobStore::stats`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StoreStats {
    pub artifact_count: usize,
    pub blob_count: usize,
    pub manifest_bytes: u64,
    pub compressed_blob_bytes: u64,
    pub total_store_bytes: u64,
}

/// Private content-addressed `zstd` blob and manifest store rooted at `BoundScope::store_dir()`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    workspace_scope_id: context_core::WorkspaceScopeId,
    store_dir: PathBuf,
    blobs_dir: PathBuf,
    manifests_dir: PathBuf,
    tmp_dir: PathBuf,
    secret_guard: SecretGuard,
    budget: ReductionBudget,
    zstd_level: i32,
    mint_counter: Arc<AtomicU64>,
}

impl BlobStore {
    /// Opens or initializes the private blob store for `scope` using default `SecretGuard` and `ReductionBudget`.
    pub fn open(scope: &BoundScope) -> Result<Self> {
        Self::open_with_config(scope, SecretGuard::default(), ReductionBudget::default())
    }

    /// Opens or initializes the private blob store for `scope` with explicit `secret_guard` and `budget`.
    pub fn open_with_config(
        scope: &BoundScope,
        secret_guard: SecretGuard,
        budget: ReductionBudget,
    ) -> Result<Self> {
        budget.validate()?;

        let engine_dir = scope.engine_dir();
        let store_dir = scope.store_dir();
        let blobs_dir = store_dir.join("blobs");
        let manifests_dir = store_dir.join("manifests");
        let tmp_dir = store_dir.join("tmp");

        let newly_created = !store_dir.exists();
        fs::create_dir_all(&engine_dir)?;
        fs::create_dir_all(&store_dir)?;

        let sentinel = store_dir.join(ACL_SENTINEL_FILE);
        if newly_created || !sentinel.exists() {
            let _ = apply_private_dir_permissions(&engine_dir);
            apply_private_dir_permissions(&store_dir)?;
        }

        fs::create_dir_all(&blobs_dir)?;
        fs::create_dir_all(&manifests_dir)?;
        fs::create_dir_all(&tmp_dir)?;

        if newly_created || !sentinel.exists() {
            #[cfg(unix)]
            {
                apply_private_dir_permissions(&blobs_dir)?;
                apply_private_dir_permissions(&manifests_dir)?;
                apply_private_dir_permissions(&tmp_dir)?;
            }
            fs::write(&sentinel, b"acl_version=1\n")?;
            apply_private_file_permissions(&sentinel)?;
        }

        Ok(Self {
            workspace_scope_id: scope.workspace_scope_id.clone(),
            store_dir,
            blobs_dir,
            manifests_dir,
            tmp_dir,
            secret_guard,
            budget,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            mint_counter: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Root `.context-engine/store` directory path.
    #[must_use]
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// Active [`ReductionBudget`].
    #[must_use]
    pub const fn budget(&self) -> &ReductionBudget {
        &self.budget
    }

    /// Active [`SecretGuard`].
    #[must_use]
    pub const fn secret_guard(&self) -> &SecretGuard {
        &self.secret_guard
    }

    /// Overrides the `zstd` compression level (`1..=19`).
    #[must_use]
    pub const fn with_zstd_level(mut self, level: i32) -> Self {
        self.zstd_level = level;
        self
    }

    /// Re-applies owner-only private directory permissions on `.context-engine/store`.
    pub fn tighten_permissions(&self) -> Result<()> {
        apply_private_dir_permissions(&self.store_dir)
    }

    /// Verifies that `.context-engine/store` enforces private owner-only permissions (`doctor` helper).
    pub fn verify_store_permissions(&self) -> Result<StorePermissionReport> {
        verify_directory_permissions(&self.store_dir)
    }

    /// Computes the content-addressed `.zst` path `blobs/<2-hex>/<sha256>.zst` for a validated digest.
    pub fn blob_path_for_sha256(&self, sha256: &str) -> Result<PathBuf> {
        validate_sha256_hex(sha256)?;
        Ok(self
            .blobs_dir
            .join(&sha256[..2])
            .join(format!("{sha256}.zst")))
    }

    /// Computes the manifest JSON path `manifests/<artifact_id>.json`.
    pub fn manifest_path_for_id(&self, artifact_id: &ArtifactId) -> Result<PathBuf> {
        ArtifactId::parse(artifact_id.as_str())?;
        Ok(self
            .manifests_dir
            .join(format!("{}.json", artifact_id.as_str())))
    }

    /// Protects `raw_bytes` through [`SecretGuard::protect_bytes`] and atomically persists the
    /// resulting `zstd`-compressed content-addressed blob when permitted by policy.
    pub fn put_blob(&self, raw_bytes: &[u8]) -> Result<ProtectedBlobOutcome> {
        let protection = self.secret_guard.protect_bytes(raw_bytes)?;
        self.persist_protected_outcome(raw_bytes, protection)
    }

    /// Protects and persists all streams for an artifact atomically along with its scoped
    /// `manifests/<artifact_id>.json` binding `(workspace_scope_id, session_id, ArtifactEnvelope)`.
    pub fn put_artifact_streams(
        &self,
        scope: &BoundScope,
        request: PutArtifactRequest<'_>,
    ) -> Result<StoredArtifactOutcome> {
        self.ensure_store_workspace(scope)?;

        // Phase 1: Run `SecretGuard` on `request.source` metadata (`argv` / `label`) AND all streams
        // in memory BEFORE touching disk so `SecretPolicyMode::Deny` leaves zero partial blobs behind
        // and secrets passed in command arguments never leak into `ArtifactEnvelope` or manifests.
        let (sanitized_source, source_redacted_count, source_rule_ids) =
            sanitize_artifact_source(&self.secret_guard, request.source)?;

        let mut protected_inputs = Vec::with_capacity(request.streams.len());
        for input in &request.streams {
            let outcome = self.secret_guard.protect_bytes(input.bytes)?;
            protected_inputs.push((input, outcome));
        }

        // Phase 2: Persist allowed `.zst` blobs atomically.
        let mut stream_refs: Vec<StoredStreamRef> = Vec::with_capacity(protected_inputs.len());
        let mut sanitized_streams: Vec<(StreamKind, Option<String>)> =
            Vec::with_capacity(protected_inputs.len());
        let mut all_rule_ids: BTreeSet<String> = source_rule_ids;
        let mut total_secrets_redacted = source_redacted_count;

        for (input, protection) in protected_inputs {
            let persisted = self.persist_protected_outcome(input.bytes, protection)?;
            total_secrets_redacted =
                total_secrets_redacted.saturating_add(persisted.findings.len());
            for f in &persisted.findings {
                all_rule_ids.insert(f.rule_id.to_string());
            }

            let secret_rule_ids: Vec<String> = persisted
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            sanitized_streams.push((input.stream, persisted.sanitized_index_text));
            stream_refs.push(StoredStreamRef {
                stream: input.stream,
                raw_sha256: persisted.raw_sha256,
                raw_bytes: persisted.raw_bytes,
                stored_sha256: persisted.stored_sha256,
                stored_bytes: persisted.stored_bytes,
                compressed_bytes: persisted.compressed_bytes,
                encoding: persisted.encoding,
                truncated: input.truncated,
                exact_raw_preserved: persisted.exact_raw_preserved,
                originals_available: persisted.originals_available,
                quarantined: persisted.quarantined,
                secrets_redacted: persisted.findings.len(),
                secret_rule_ids,
            });
        }

        // Phase 3: Assemble `CaptureSummary`, `ArtifactId`, `RecoveryHandle`, and `ArtifactEnvelope`.
        let capture_summary = build_capture_summary(
            &stream_refs,
            request.capture_complete,
            total_secrets_redacted,
            all_rule_ids.into_iter().collect(),
        );

        let artifact_id = match request.artifact_id {
            Some(existing) => ArtifactId::parse(existing.as_str())?,
            None => ArtifactId::mint(
                scope,
                sanitized_source.captured_at(),
                self.next_mint_nonce(),
                &capture_summary.stdout_sha256,
                Some(&capture_summary.stderr_sha256),
            ),
        };

        let any_quarantined = stream_refs.iter().any(|s| s.quarantined);
        let recovery = if capture_summary.originals_available {
            RecoveryHandle::for_artifact(artifact_id.clone(), Some(self.budget.max_get_bytes))
        } else if any_quarantined {
            RecoveryHandle::unavailable(
                artifact_id.clone(),
                "quarantined by workspace secret policy",
            )
        } else {
            RecoveryHandle::unavailable(
                artifact_id.clone(),
                "originals unavailable after binary secret redaction",
            )
        };

        let view = request.view.unwrap_or_else(|| {
            let mut transforms = Vec::new();
            if total_secrets_redacted > 0 {
                transforms.push(TRANSFORM_SECRET_REDACT_V1.to_string());
            }
            transforms.push(TRANSFORM_UNKNOWN_SAFE_V1.to_string());
            ArtifactView {
                kind: ViewKind::UnknownSafe,
                reducer_version: "1".to_string(),
                omitted: capture_summary.stdout_bytes + capture_summary.stderr_bytes > 0,
                safe_excerpt: format!(
                    "captured {} stdout bytes, {} stderr bytes",
                    capture_summary.stdout_bytes, capture_summary.stderr_bytes
                ),
                transformations: transforms,
                reduction_error: None,
                failure_identifiers: Vec::new(),
            }
        });

        let envelope = ArtifactEnvelope::new_v1(
            scope,
            artifact_id.clone(),
            sanitized_source,
            capture_summary,
            view,
            recovery,
        );
        envelope.validate(scope)?;

        let now_ms = current_unix_ms();
        let scope_binding_sha256 = compute_scope_binding_sha256(
            &scope.workspace_scope_id,
            &scope.session_id,
            &artifact_id,
            &stream_refs,
        );

        let manifest = StoredArtifactManifest {
            manifest_version: MANIFEST_SCHEMA_VERSION,
            artifact_id,
            workspace_scope_id: scope.workspace_scope_id.clone(),
            session_id: scope.session_id.clone(),
            scope_binding_sha256,
            created_at_unix_ms: now_ms,
            last_accessed_unix_ms: now_ms,
            envelope: envelope.clone(),
            streams: stream_refs,
        };

        self.write_manifest_atomic(&manifest)?;

        Ok(StoredArtifactOutcome {
            manifest,
            envelope,
            sanitized_streams,
        })
    }

    /// Updates `envelope.view` in an existing artifact manifest after verifying `caller_scope`.
    pub fn update_artifact_view(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
        view: ArtifactView,
    ) -> Result<ArtifactEnvelope> {
        let mut manifest = self.load_verified_manifest(caller_scope, artifact_id)?;
        manifest.envelope.view = view;
        manifest.envelope.validate(caller_scope)?;
        manifest.last_accessed_unix_ms = current_unix_ms();
        self.write_manifest_atomic(&manifest)?;
        Ok(manifest.envelope)
    }

    /// Loads and verifies the scoped [`StoredArtifactManifest`] for `artifact_id`.
    pub fn get_manifest(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
    ) -> Result<StoredArtifactManifest> {
        self.load_verified_manifest(caller_scope, artifact_id)
    }

    /// Decompresses, SHA-256-verifies, and returns a bounded `[start, end)` byte range from
    /// `artifact_id` (`stream`), supporting arbitrary binary and non-UTF-8 payloads.
    pub fn get_bytes(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
        stream: StreamKind,
        range: ByteRange,
    ) -> Result<ByteSlicePage> {
        let validated_range =
            ByteRange::new(range.start, range.end, self.budget.max_get_bytes)?;
        let mut manifest = self.load_verified_manifest(caller_scope, artifact_id)?;
        let loaded = self.load_and_verify_stream(&manifest, stream)?;

        self.touch_manifest_lru(&mut manifest);

        let total_bytes = loaded.bytes.len() as u64;
        let total_lines = std::str::from_utf8(&loaded.bytes).ok().map(count_lines_str);

        let (slice, returned_range, has_more) = if validated_range.start >= total_bytes {
            (
                Vec::new(),
                ByteRange {
                    start: total_bytes,
                    end: total_bytes,
                },
                false,
            )
        } else {
            let clamped_end = validated_range.end.min(total_bytes);
            let start_idx = usize::try_from(validated_range.start).unwrap_or(usize::MAX);
            let end_idx = usize::try_from(clamped_end).unwrap_or(usize::MAX);
            (
                loaded.bytes[start_idx..end_idx].to_vec(),
                ByteRange {
                    start: validated_range.start,
                    end: clamped_end,
                },
                clamped_end < total_bytes,
            )
        };

        Ok(ByteSlicePage {
            artifact_id: artifact_id.clone(),
            stream: loaded.resolved_stream,
            sha256: loaded.sha256,
            encoding: loaded.encoding,
            exact_raw_preserved: loaded.exact_raw_preserved,
            total_bytes,
            total_lines,
            returned_range,
            has_more,
            bytes: slice,
        })
    }

    /// Decompresses, SHA-256-verifies, and returns a 1-indexed inclusive `[start_line, end_line]`
    /// derived UTF-8 (or lossy UTF-8 for binary/non-UTF-8) line page from `artifact_id`.
    pub fn get_lines(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
        stream: StreamKind,
        range: LineRange,
    ) -> Result<LineSlicePage> {
        let validated_range =
            LineRange::new(range.start_line, range.end_line, self.budget.max_get_lines)?;
        let mut manifest = self.load_verified_manifest(caller_scope, artifact_id)?;
        let loaded = self.load_and_verify_stream(&manifest, stream)?;

        self.touch_manifest_lru(&mut manifest);

        let total_bytes = loaded.bytes.len() as u64;
        let (derived_text, derived_encoding): (Cow<'_, str>, StreamEncoding) =
            match std::str::from_utf8(&loaded.bytes) {
                Ok(valid_utf8) => (Cow::Borrowed(valid_utf8), StreamEncoding::Utf8),
                Err(_) => (
                    String::from_utf8_lossy(&loaded.bytes),
                    StreamEncoding::Utf8Lossy,
                ),
            };

        let all_lines: Vec<&str> = derived_text.lines().collect();
        let total_lines = all_lines.len();

        if total_lines == 0 || validated_range.start_line > total_lines {
            return Ok(LineSlicePage {
                artifact_id: artifact_id.clone(),
                stream: loaded.resolved_stream,
                sha256: loaded.sha256,
                encoding: derived_encoding,
                exact_raw_preserved: loaded.exact_raw_preserved,
                total_bytes,
                total_lines,
                returned_range: None,
                has_more: false,
                byte_budget_truncated: false,
                lines: Vec::new(),
                text: String::new(),
            });
        }

        let clamped_end_line = validated_range.end_line.min(total_lines);
        let max_bytes = self.budget.max_get_bytes;

        let mut indexed_lines: Vec<IndexedLine> = Vec::new();
        let mut joined_text = String::new();
        let mut byte_budget_truncated = false;

        for line_num in validated_range.start_line..=clamped_end_line {
            let raw_line = all_lines[line_num - 1];
            let sep_len = usize::from(!indexed_lines.is_empty());

            if joined_text.len() + sep_len + raw_line.len() <= max_bytes {
                if sep_len > 0 {
                    joined_text.push('\n');
                }
                joined_text.push_str(raw_line);
                indexed_lines.push(IndexedLine {
                    line_number: line_num,
                    content: raw_line.to_string(),
                });
            } else {
                byte_budget_truncated = true;
                // Always return at least a UTF-8-bounded prefix of the first requested line.
                if indexed_lines.is_empty() {
                    let (prefix, _) = truncate_str_utf8_boundary(raw_line, max_bytes);
                    joined_text.push_str(prefix);
                    indexed_lines.push(IndexedLine {
                        line_number: line_num,
                        content: prefix.to_string(),
                    });
                }
                break;
            }
        }

        let actual_end = indexed_lines
            .last()
            .map_or(validated_range.start_line, |l| l.line_number);
        let returned_range = if indexed_lines.is_empty() {
            None
        } else {
            Some(LineRange {
                start_line: validated_range.start_line,
                end_line: actual_end,
            })
        };
        let has_more = actual_end < total_lines || byte_budget_truncated;

        Ok(LineSlicePage {
            artifact_id: artifact_id.clone(),
            stream: loaded.resolved_stream,
            sha256: loaded.sha256,
            encoding: derived_encoding,
            exact_raw_preserved: loaded.exact_raw_preserved,
            total_bytes,
            total_lines,
            returned_range,
            has_more,
            byte_budget_truncated,
            lines: indexed_lines,
            text: joined_text,
        })
    }

    /// Enforces the configured `ReductionBudget::retention_ttl_secs` and
    /// `ReductionBudget::max_workspace_store_bytes` on this store.
    pub fn enforce_quota_and_ttl(&self) -> Result<PruneReport> {
        self.prune(PrunePolicy {
            ttl_secs: Some(self.budget.retention_ttl_secs),
            max_store_bytes: Some(self.budget.max_workspace_store_bytes),
            now_unix_ms: None,
        })
    }

    /// Prunes expired manifests, evicts LRU/oldest artifacts to satisfy `policy.max_store_bytes`,
    /// and removes unreferenced `.zst` blobs and leftover temp files.
    pub fn prune(&self, policy: PrunePolicy) -> Result<PruneReport> {
        let now_ms = policy.now_unix_ms.unwrap_or_else(current_unix_ms);
        let mut report = PruneReport::default();

        // 1. Clean up stale temp files inside `tmp/`.
        if self.tmp_dir.exists() {
            for entry in fs::read_dir(&self.tmp_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let size = entry.metadata().map_or(0, |m| m.len());
                    if fs::remove_file(&path).is_ok() {
                        report.removed_temp_files += 1;
                        report.freed_bytes = report.freed_bytes.saturating_add(size);
                    }
                }
            }
        }

        // 2. Inventory all manifests and blobs on disk.
        let mut manifests = self.scan_all_manifests()?;
        let blob_inventory = self.scan_all_blobs()?;

        let mut evicted_indices: BTreeSet<usize> = BTreeSet::new();

        // 3. Phase A: Mark TTL-expired manifests.
        if let Some(ttl_secs) = policy.ttl_secs {
            let ttl_ms = ttl_secs.saturating_mul(1_000);
            for (idx, item) in manifests.iter().enumerate() {
                let age_ms = now_ms.saturating_sub(item.manifest.created_at_unix_ms);
                let expired = if ttl_ms == 0 {
                    true
                } else {
                    age_ms > ttl_ms
                };
                if expired {
                    evicted_indices.insert(idx);
                    report.expired_artifacts += 1;
                }
            }
        }

        // 4. Phase B: Enforce workspace byte quota using LRU (`last_accessed_unix_ms` ASC,
        // `created_at_unix_ms` ASC, `artifact_id` ASC).
        if let Some(max_bytes) = policy.max_store_bytes {
            let mut candidate_order: Vec<usize> = (0..manifests.len())
                .filter(|idx| !evicted_indices.contains(idx))
                .collect();
            candidate_order.sort_by(|&a, &b| {
                let ma = &manifests[a].manifest;
                let mb = &manifests[b].manifest;
                ma.last_accessed_unix_ms
                    .cmp(&mb.last_accessed_unix_ms)
                    .then_with(|| ma.created_at_unix_ms.cmp(&mb.created_at_unix_ms))
                    .then_with(|| ma.artifact_id.cmp(&mb.artifact_id))
            });

            for candidate_idx in candidate_order {
                let live_bytes = compute_live_footprint(&manifests, &evicted_indices, &blob_inventory);
                if live_bytes <= max_bytes {
                    break;
                }
                evicted_indices.insert(candidate_idx);
                report.quota_evicted_artifacts += 1;
            }
        }

        // 5. Crash-safe deletion order: remove evicted manifests FIRST so no manifest ever
        // dangles onto a deleted content-addressed blob.
        for &idx in &evicted_indices {
            let entry = &manifests[idx];
            match fs::remove_file(&entry.path) {
                Ok(()) => {
                    report.removed_manifests += 1;
                    report.freed_bytes = report.freed_bytes.saturating_add(entry.size_bytes);
                    report
                        .evicted_artifact_ids
                        .push(entry.manifest.artifact_id.clone());
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(ContextError::Io(err)),
            }
        }

        // 6. Compute live blob reference set from remaining manifests and sweep unreferenced blobs.
        let mut live_blob_shas: BTreeSet<String> = BTreeSet::new();
        let mut remaining_manifest_bytes = 0u64;
        let mut remaining_artifacts = 0usize;

        for (idx, item) in manifests.drain(..).enumerate() {
            if evicted_indices.contains(&idx) {
                continue;
            }
            remaining_artifacts += 1;
            remaining_manifest_bytes = remaining_manifest_bytes.saturating_add(item.size_bytes);
            for s in &item.manifest.streams {
                if let Some(sha) = &s.stored_sha256 {
                    live_blob_shas.insert(sha.clone());
                }
            }
        }

        let mut remaining_blobs = 0usize;
        let mut remaining_blob_bytes = 0u64;

        for (sha, (blob_path, blob_size)) in blob_inventory {
            if live_blob_shas.contains(&sha) {
                remaining_blobs += 1;
                remaining_blob_bytes = remaining_blob_bytes.saturating_add(blob_size);
            } else {
                match fs::remove_file(&blob_path) {
                    Ok(()) => {
                        report.removed_blobs += 1;
                        report.freed_bytes = report.freed_bytes.saturating_add(blob_size);
                    }
                    Err(err) if err.kind() == ErrorKind::NotFound => {}
                    Err(err) => return Err(ContextError::Io(err)),
                }
            }
        }

        report.remaining_artifacts = remaining_artifacts;
        report.remaining_blobs = remaining_blobs;
        report.remaining_bytes = remaining_manifest_bytes.saturating_add(remaining_blob_bytes);

        Ok(report)
    }

    /// Computes aggregate store metrics (`artifact_count`, `blob_count`, byte totals).
    pub fn stats(&self) -> Result<StoreStats> {
        let manifests = self.scan_all_manifests()?;
        let blobs = self.scan_all_blobs()?;

        let manifest_bytes: u64 = manifests.iter().map(|m| m.size_bytes).sum();
        let compressed_blob_bytes: u64 = blobs.values().map(|(_, sz)| *sz).sum();

        Ok(StoreStats {
            artifact_count: manifests.len(),
            blob_count: blobs.len(),
            manifest_bytes,
            compressed_blob_bytes,
            total_store_bytes: manifest_bytes.saturating_add(compressed_blob_bytes),
        })
    }

    fn ensure_store_workspace(&self, scope: &BoundScope) -> Result<()> {
        if scope.workspace_scope_id != self.workspace_scope_id {
            return Err(ContextError::ScopeViolation {
                expected_workspace: self.workspace_scope_id.as_str().to_string(),
                actual_workspace: scope.workspace_scope_id.as_str().to_string(),
                detail: "caller BoundScope does not match opened BlobStore workspace".to_string(),
            });
        }
        Ok(())
    }

    fn next_mint_nonce(&self) -> u64 {
        let seq = self.mint_counter.fetch_add(1, Ordering::Relaxed);
        let time_mix = current_unix_ms();
        time_mix.wrapping_mul(1_000_003).wrapping_add(seq)
    }

    fn persist_protected_outcome(
        &self,
        raw_bytes: &[u8],
        protection: context_core::StreamProtectionOutcome,
    ) -> Result<ProtectedBlobOutcome> {
        let raw_sha256 = sha256_hex(raw_bytes);
        let raw_len = raw_bytes.len() as u64;

        if !protection.originals_available || protection.quarantined {
            let encoding = StreamEncoding::detect(raw_bytes);
            return Ok(ProtectedBlobOutcome {
                raw_sha256,
                raw_bytes: raw_len,
                stored_sha256: None,
                stored_bytes: 0,
                compressed_bytes: 0,
                encoding,
                sanitized_index_text: protection.sanitized_index_text,
                findings: protection.findings,
                exact_raw_preserved: false,
                originals_available: false,
                quarantined: protection.quarantined,
            });
        }

        let stored_len = protection.persistence_bytes.len() as u64;
        let encoding = StreamEncoding::detect(&protection.persistence_bytes);
        let (stored_sha256, compressed_bytes) =
            self.write_zstd_blob_atomic(&protection.persistence_bytes)?;

        Ok(ProtectedBlobOutcome {
            raw_sha256,
            raw_bytes: raw_len,
            stored_sha256: Some(stored_sha256),
            stored_bytes: stored_len,
            compressed_bytes,
            encoding,
            sanitized_index_text: protection.sanitized_index_text,
            findings: protection.findings,
            exact_raw_preserved: protection.exact_raw_preserved,
            originals_available: true,
            quarantined: false,
        })
    }

    fn write_zstd_blob_atomic(&self, uncompressed: &[u8]) -> Result<(String, u64)> {
        let expected_sha256 = sha256_hex(uncompressed);
        let shard_dir = self.blobs_dir.join(&expected_sha256[..2]);
        fs::create_dir_all(&shard_dir)?;
        let final_path = shard_dir.join(format!("{expected_sha256}.zst"));

        if final_path.exists()
            && self
                .read_and_verify_blob(&final_path, &expected_sha256)
                .is_ok()
        {
            let size = fs::metadata(&final_path)?.len();
            return Ok((expected_sha256, size));
        }

        let compressed = zstd::stream::encode_all(Cursor::new(uncompressed), self.zstd_level)
            .map_err(|err| ContextError::Storage {
                message: format!("zstd compression failed: {err}"),
            })?;

        // Verify SHA-256 round-trip of compressed frame before committing to store.
        let verify_decoded =
            zstd::stream::decode_all(Cursor::new(&compressed)).map_err(|err| {
                ContextError::Storage {
                    message: format!("zstd pre-commit verification failed: {err}"),
                }
            })?;
        let verify_sha = sha256_hex(&verify_decoded);
        if verify_sha != expected_sha256 {
            return Err(ContextError::IntegrityMismatch {
                expected_sha256,
                actual_sha256: verify_sha,
            });
        }

        fs::create_dir_all(&self.tmp_dir)?;
        let mut tmp = TempBuilder::new()
            .prefix("blob-")
            .suffix(".tmp")
            .tempfile_in(&self.tmp_dir)?;
        tmp.write_all(&compressed)?;
        tmp.flush()?;
        tmp.as_file().sync_all()?;
        apply_private_file_permissions(tmp.path())?;

        match tmp.persist(&final_path) {
            Ok(_) => Ok((expected_sha256, compressed.len() as u64)),
            Err(persist_err) => {
                // Content-addressed race safety (especially on Windows if a concurrent reader
                // holds an identical verified blob open).
                if final_path.exists()
                    && self
                        .read_and_verify_blob(&final_path, &expected_sha256)
                        .is_ok()
                {
                    let size = fs::metadata(&final_path)?.len();
                    return Ok((expected_sha256, size));
                }
                Err(ContextError::Io(persist_err.error))
            }
        }
    }

    fn write_manifest_atomic(&self, manifest: &StoredArtifactManifest) -> Result<()> {
        self.write_manifest_internal(manifest, true)
    }

    fn touch_manifest_lru(&self, manifest: &mut StoredArtifactManifest) {
        let now_ms = current_unix_ms();
        if now_ms > manifest.last_accessed_unix_ms {
            manifest.last_accessed_unix_ms = now_ms;
            let _ = self.write_manifest_internal(manifest, false);
        }
    }

    fn write_manifest_internal(
        &self,
        manifest: &StoredArtifactManifest,
        durable_sync: bool,
    ) -> Result<()> {
        let final_path = self.manifest_path_for_id(&manifest.artifact_id)?;
        let json_bytes = serde_json::to_vec_pretty(manifest)?;

        fs::create_dir_all(&self.tmp_dir)?;
        let mut tmp = TempBuilder::new()
            .prefix("manifest-")
            .suffix(".tmp")
            .tempfile_in(&self.tmp_dir)?;
        tmp.write_all(&json_bytes)?;
        tmp.flush()?;
        if durable_sync {
            tmp.as_file().sync_all()?;
        }
        apply_private_file_permissions(tmp.path())?;
        tmp.persist(&final_path)
            .map_err(|err| ContextError::Io(err.error))?;
        Ok(())
    }

    fn load_verified_manifest(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
    ) -> Result<StoredArtifactManifest> {
        let parsed_id = ArtifactId::parse(artifact_id.as_str())?;
        self.ensure_store_workspace(caller_scope)?;

        let path = self.manifest_path_for_id(&parsed_id)?;
        let bytes = fs::read(&path).map_err(|err| match err.kind() {
            ErrorKind::NotFound => ContextError::ArtifactNotFound {
                artifact_id: parsed_id.as_str().to_string(),
            },
            _ => ContextError::Io(err),
        })?;

        let manifest: StoredArtifactManifest = serde_json::from_slice(&bytes)?;
        if manifest.manifest_version != MANIFEST_SCHEMA_VERSION {
            return Err(ContextError::Storage {
                message: format!(
                    "unsupported manifest_version {} (expected {MANIFEST_SCHEMA_VERSION})",
                    manifest.manifest_version
                ),
            });
        }

        if manifest.artifact_id != parsed_id {
            return Err(ContextError::IntegrityMismatch {
                expected_sha256: parsed_id.as_str().to_string(),
                actual_sha256: manifest.artifact_id.as_str().to_string(),
            });
        }

        // Enforce server-bound workspace AND session isolation before inspecting blob pointers!
        parsed_id.verify_binding(
            &manifest.workspace_scope_id,
            &manifest.session_id,
            caller_scope,
        )?;

        let expected_binding = compute_scope_binding_sha256(
            &manifest.workspace_scope_id,
            &manifest.session_id,
            &manifest.artifact_id,
            &manifest.streams,
        );
        if manifest.scope_binding_sha256 != expected_binding {
            return Err(ContextError::IntegrityMismatch {
                expected_sha256: expected_binding,
                actual_sha256: manifest.scope_binding_sha256,
            });
        }

        manifest.envelope.validate(caller_scope)?;
        Ok(manifest)
    }

    fn load_and_verify_stream(
        &self,
        manifest: &StoredArtifactManifest,
        requested_stream: StreamKind,
    ) -> Result<LoadedStream> {
        if requested_stream == StreamKind::Combined {
            if manifest.streams.len() == 1 && manifest.streams[0].stream == StreamKind::Document {
                return self.load_single_stream_ref(&manifest.artifact_id, &manifest.streams[0]);
            }

            let mut combined = Vec::new();
            let mut exact_raw_preserved = true;
            for target in [StreamKind::Stdout, StreamKind::Stderr] {
                if let Some(sref) = manifest.streams.iter().find(|s| s.stream == target) {
                    let part = self.load_single_stream_ref(&manifest.artifact_id, sref)?;
                    exact_raw_preserved &= part.exact_raw_preserved;
                    if !combined.is_empty()
                        && !combined.ends_with(b"\n")
                        && !part.bytes.is_empty()
                    {
                        combined.push(b'\n');
                    }
                    combined.extend_from_slice(&part.bytes);
                }
            }
            let sha256 = sha256_hex(&combined);
            let encoding = StreamEncoding::detect(&combined);
            return Ok(LoadedStream {
                resolved_stream: StreamKind::Combined,
                bytes: combined,
                sha256,
                encoding,
                exact_raw_preserved,
            });
        }

        let stream_ref = manifest
            .streams
            .iter()
            .find(|s| s.stream == requested_stream)
            .or_else(|| {
                // Allow ergonomic `Stdout` <-> `Document` lookup on single-stream document artifacts.
                if matches!(requested_stream, StreamKind::Stdout | StreamKind::Document)
                    && manifest.streams.len() == 1
                    && matches!(
                        manifest.streams[0].stream,
                        StreamKind::Stdout | StreamKind::Document
                    )
                {
                    Some(&manifest.streams[0])
                } else {
                    None
                }
            })
            .ok_or_else(|| ContextError::Storage {
                message: format!(
                    "stream '{}' is not present in artifact '{}'",
                    requested_stream, manifest.artifact_id
                ),
            })?;

        self.load_single_stream_ref(&manifest.artifact_id, stream_ref)
    }

    fn load_single_stream_ref(
        &self,
        artifact_id: &ArtifactId,
        stream_ref: &StoredStreamRef,
    ) -> Result<LoadedStream> {
        if stream_ref.quarantined {
            return Err(ContextError::SecretQuarantined {
                artifact_id: artifact_id.as_str().to_string(),
                reason: "stream is quarantined by workspace secret policy".to_string(),
            });
        }
        if !stream_ref.originals_available {
            return Err(ContextError::SecretQuarantined {
                artifact_id: artifact_id.as_str().to_string(),
                reason: "stream originals are unavailable under active secret policy".to_string(),
            });
        }
        let Some(expected_sha) = &stream_ref.stored_sha256 else {
            return Err(ContextError::Storage {
                message: format!(
                    "artifact '{}' stream '{}' has no stored blob pointer",
                    artifact_id, stream_ref.stream
                ),
            });
        };

        let blob_path = self.blob_path_for_sha256(expected_sha)?;
        let bytes = self.read_and_verify_blob(&blob_path, expected_sha)?;

        Ok(LoadedStream {
            resolved_stream: stream_ref.stream,
            bytes,
            sha256: expected_sha.clone(),
            encoding: stream_ref.encoding,
            exact_raw_preserved: stream_ref.exact_raw_preserved,
        })
    }

    fn read_and_verify_blob(&self, blob_path: &Path, expected_sha256: &str) -> Result<Vec<u8>> {
        let compressed = fs::read(blob_path).map_err(|err| match err.kind() {
            ErrorKind::NotFound => ContextError::Storage {
                message: format!(
                    "missing content-addressed blob '{}' for sha256 {expected_sha256}",
                    blob_path.display()
                ),
            },
            _ => ContextError::Io(err),
        })?;

        let decompressed =
            zstd::stream::decode_all(Cursor::new(&compressed)).map_err(|err| {
                ContextError::IntegrityMismatch {
                    expected_sha256: expected_sha256.to_string(),
                    actual_sha256: format!("<corrupt-zstd-frame: {err}>"),
                }
            })?;

        let actual_sha256 = sha256_hex(&decompressed);
        if actual_sha256 != expected_sha256 {
            return Err(ContextError::IntegrityMismatch {
                expected_sha256: expected_sha256.to_string(),
                actual_sha256,
            });
        }

        Ok(decompressed)
    }

    fn scan_all_manifests(&self) -> Result<Vec<ManifestDiskEntry>> {
        let mut entries = Vec::new();
        if !self.manifests_dir.exists() {
            return Ok(entries);
        }

        for dir_entry in fs::read_dir(&self.manifests_dir)? {
            let dir_entry = dir_entry?;
            let path = dir_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let size_bytes = dir_entry.metadata().map_or(0, |m| m.len());
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(manifest) = serde_json::from_slice::<StoredArtifactManifest>(&bytes) {
                    entries.push(ManifestDiskEntry {
                        path,
                        size_bytes,
                        manifest,
                    });
                }
            }
        }
        Ok(entries)
    }

    fn scan_all_blobs(&self) -> Result<BTreeMap<String, (PathBuf, u64)>> {
        let mut blobs = BTreeMap::new();
        if !self.blobs_dir.exists() {
            return Ok(blobs);
        }

        for shard in fs::read_dir(&self.blobs_dir)? {
            let shard = shard?;
            let shard_path = shard.path();
            if !shard_path.is_dir() {
                continue;
            }
            for file_entry in fs::read_dir(&shard_path)? {
                let file_entry = file_entry?;
                let file_path = file_entry.path();
                if file_path.extension().and_then(|e| e.to_str()) != Some("zst") {
                    continue;
                }
                if let Some(stem) = file_path.file_stem().and_then(|s| s.to_str()) {
                    let size = file_entry.metadata().map_or(0, |m| m.len());
                    blobs.insert(stem.to_string(), (file_path, size));
                }
            }
        }

        Ok(blobs)
    }
}

struct LoadedStream {
    resolved_stream: StreamKind,
    bytes: Vec<u8>,
    sha256: String,
    encoding: StreamEncoding,
    exact_raw_preserved: bool,
}

struct ManifestDiskEntry {
    path: PathBuf,
    size_bytes: u64,
    manifest: StoredArtifactManifest,
}

fn compute_live_footprint(
    manifests: &[ManifestDiskEntry],
    evicted_indices: &BTreeSet<usize>,
    blobs: &BTreeMap<String, (PathBuf, u64)>,
) -> u64 {
    let mut manifest_bytes = 0u64;
    let mut referenced_shas: BTreeSet<&str> = BTreeSet::new();

    for (idx, item) in manifests.iter().enumerate() {
        if evicted_indices.contains(&idx) {
            continue;
        }
        manifest_bytes = manifest_bytes.saturating_add(item.size_bytes);
        for s in &item.manifest.streams {
            if let Some(sha) = &s.stored_sha256 {
                referenced_shas.insert(sha.as_str());
            }
        }
    }

    let mut blob_bytes = 0u64;
    for sha in referenced_shas {
        if let Some((_, sz)) = blobs.get(sha) {
            blob_bytes = blob_bytes.saturating_add(*sz);
        }
    }

    manifest_bytes.saturating_add(blob_bytes)
}

fn build_capture_summary(
    streams: &[StoredStreamRef],
    capture_complete: bool,
    secrets_redacted: usize,
    secret_rule_ids: Vec<String>,
) -> CaptureSummary {
    if streams.len() == 1 && streams[0].stream == StreamKind::Document {
        let doc = &streams[0];
        return CaptureSummary {
            stdout_sha256: doc.raw_sha256.clone(),
            stderr_sha256: EMPTY_SHA256_HEX.to_string(),
            stdout_bytes: doc.raw_bytes,
            stderr_bytes: 0,
            stdout_truncated: doc.truncated,
            stderr_truncated: false,
            complete: capture_complete && !doc.truncated,
            encoding: doc.encoding,
            originals_available: doc.originals_available && !doc.quarantined,
            secrets_redacted,
            secret_rule_ids,
        };
    }

    let stdout_ref = streams.iter().find(|s| s.stream == StreamKind::Stdout);
    let stderr_ref = streams.iter().find(|s| s.stream == StreamKind::Stderr);

    let stdout_sha256 = stdout_ref
        .map_or_else(|| EMPTY_SHA256_HEX.to_string(), |s| s.raw_sha256.clone());
    let stderr_sha256 = stderr_ref
        .map_or_else(|| EMPTY_SHA256_HEX.to_string(), |s| s.raw_sha256.clone());
    let stdout_bytes = stdout_ref.map_or(0, |s| s.raw_bytes);
    let stderr_bytes = stderr_ref.map_or(0, |s| s.raw_bytes);
    let stdout_truncated = stdout_ref.is_some_and(|s| s.truncated);
    let stderr_truncated = stderr_ref.is_some_and(|s| s.truncated);

    let out_enc = stdout_ref.map_or(StreamEncoding::Utf8, |s| s.encoding);
    let err_enc = stderr_ref.map_or(StreamEncoding::Utf8, |s| s.encoding);
    let encoding = match (out_enc, err_enc) {
        (StreamEncoding::Binary, _) | (_, StreamEncoding::Binary) => StreamEncoding::Binary,
        (StreamEncoding::Utf8Lossy, _) | (_, StreamEncoding::Utf8Lossy) => {
            StreamEncoding::Utf8Lossy
        }
        (StreamEncoding::Utf8, StreamEncoding::Utf8) => StreamEncoding::Utf8,
    };

    let originals_available =
        !streams.is_empty() && streams.iter().all(|s| s.originals_available && !s.quarantined);

    CaptureSummary {
        stdout_sha256,
        stderr_sha256,
        stdout_bytes,
        stderr_bytes,
        stdout_truncated,
        stderr_truncated,
        complete: capture_complete && !stdout_truncated && !stderr_truncated,
        encoding,
        originals_available,
        secrets_redacted,
        secret_rule_ids,
    }
}

fn sanitize_artifact_source(
    guard: &SecretGuard,
    source: ArtifactSource,
) -> Result<(ArtifactSource, usize, BTreeSet<String>)> {
    let mut findings_count = 0usize;
    let mut rule_ids: BTreeSet<String> = BTreeSet::new();

    let sanitized = match source {
        ArtifactSource::Command {
            argv,
            cwd_relative,
            exit_code,
            duration_ms,
            timed_out,
            captured_at,
        } => {
            let mut clean_argv = Vec::with_capacity(argv.len());
            for arg in argv {
                let scan = guard.scan_str(&arg);
                if scan.has_secrets() {
                    findings_count = findings_count.saturating_add(scan.redacted_count());
                    for id in scan.distinct_rule_ids() {
                        rule_ids.insert(id);
                    }
                }
                clean_argv.push(scan.sanitized_text);
            }
            ArtifactSource::Command {
                argv: clean_argv,
                cwd_relative,
                exit_code,
                duration_ms,
                timed_out,
                captured_at,
            }
        }
        ArtifactSource::Document {
            path_relative,
            label,
            media_type,
            captured_at,
        } => {
            let clean_label = label.map(|raw_lbl| {
                let scan = guard.scan_str(&raw_lbl);
                if scan.has_secrets() {
                    findings_count = findings_count.saturating_add(scan.redacted_count());
                    for id in scan.distinct_rule_ids() {
                        rule_ids.insert(id);
                    }
                }
                scan.sanitized_text
            });
            ArtifactSource::Document {
                path_relative,
                label: clean_label,
                media_type,
                captured_at,
            }
        }
    };

    if findings_count > 0 && guard.policy().mode == SecretPolicyMode::Deny {
        return Err(ContextError::SecretPolicyDenied {
            findings_count,
            rule_ids: rule_ids.into_iter().collect(),
        });
    }

    Ok((sanitized, findings_count, rule_ids))
}

fn validate_sha256_hex(sha256: &str) -> Result<()> {
    if sha256.len() != 64 || !sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ContextError::InvalidConfig {
            field: "sha256",
            reason: format!("expected 64 lowercase hex characters, got '{sha256}'"),
        });
    }
    Ok(())
}

fn count_lines_str(s: &str) -> usize {
    s.lines().count()
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(
            |_| u64::try_from(Utc::now().timestamp_millis().max(0)).unwrap_or(0),
            |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        )
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<BlobStore>();
    let _ = ArtifactStreamInput::new(StreamKind::Stdout, &[], false);
}
