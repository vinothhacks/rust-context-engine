//! Reference shard-reconciliation and frame-window validator fixture (`large_rust_module_source.rs`).
//! Used by paired evaluation tasks to benchmark targeted symbol search + bounded line retrieval
//! against reading an entire multi-hundred-line source module into agent context.

use std::collections::{BTreeMap, BTreeSet};

/// Maximum permitted frame window span in bytes (`32 KiB`).
pub const MAX_FRAME_WINDOW_BYTES: u64 = 32_768;

/// Minimum required hexadecimal digest length for SHA-256 identifiers.
pub const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardDescriptor {
    pub shard_prefix: String,
    pub blob_sha256: String,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub referenced_by_manifests: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFault {
    InvalidDigestLength { actual: usize },
    NonLowercaseHex { offending_char: char },
    PrefixMismatch { prefix: String, digest: String },
    ZeroByteEnvelope,
    WindowInverted { start: u64, end: u64 },
    WindowExceedsCeiling { requested_span: u64, ceiling: u64 },
    WindowOutOfStreamBounds { end: u64, stream_len: u64 },
}

/// Validates a lowercase 64-character SHA-256 hex digest and checks its 2-char shard directory.
pub fn validate_shard_digest(prefix: &str, digest: &str) -> Result<(), ValidationFault> {
    if digest.len() != SHA256_HEX_LEN {
        return Err(ValidationFault::InvalidDigestLength {
            actual: digest.len(),
        });
    }
    for ch in digest.chars() {
        if !matches!(ch, '0'..='9' | 'a'..='f') {
            return Err(ValidationFault::NonLowercaseHex { offending_char: ch });
        }
    }
    if prefix != &digest[..2] {
        return Err(ValidationFault::PrefixMismatch {
            prefix: prefix.to_string(),
            digest: digest.to_string(),
        });
    }
    Ok(())
}

/// Reconciles on-disk shard blobs against live manifest stream references and returns
/// the deterministic set of orphan SHA-256 digests eligible for garbage collection.
pub fn reconcile_orphan_shards(
    manifest_refs: &BTreeMap<String, Vec<String>>,
    disk_blobs: &[ShardDescriptor],
) -> (Vec<String>, u64) {
    let mut live_digests: BTreeSet<&str> = BTreeSet::new();
    for shas in manifest_refs.values() {
        for sha in shas {
            live_digests.insert(sha.as_str());
        }
    }

    let mut orphan_digests = Vec::new();
    let mut reclaimable_bytes = 0u64;

    for blob in disk_blobs {
        if !live_digests.contains(blob.blob_sha256.as_str()) {
            orphan_digests.push(blob.blob_sha256.clone());
            reclaimable_bytes = reclaimable_bytes.saturating_add(blob.compressed_bytes);
        }
    }

    orphan_digests.sort();
    orphan_digests.dedup();
    (orphan_digests, reclaimable_bytes)
}

/// Verifies half-open `[start, end)` byte-slice window bounds against both `MAX_FRAME_WINDOW_BYTES`
/// and the underlying `stream_total_bytes` length, returning the clamped `(start, end, has_more)`.
pub fn verify_frame_window_bounds(
    start: u64,
    end: u64,
    stream_total_bytes: u64,
) -> Result<(u64, u64, bool), ValidationFault> {
    if end < start {
        return Err(ValidationFault::WindowInverted { start, end });
    }
    let requested_span = end - start;
    if requested_span > MAX_FRAME_WINDOW_BYTES {
        return Err(ValidationFault::WindowExceedsCeiling {
            requested_span,
            ceiling: MAX_FRAME_WINDOW_BYTES,
        });
    }
    if start >= stream_total_bytes {
        return Ok((stream_total_bytes, stream_total_bytes, false));
    }
    let clamped_end = end.min(stream_total_bytes);
    let has_more = clamped_end < stream_total_bytes;
    Ok((start, clamped_end, has_more))
}

/// Computes deterministic LRU eviction order across candidate manifests until `live_bytes <= quota_bytes`.
pub fn plan_quota_eviction_order(
    mut candidates: Vec<(String, u64, u64)>,
    mut live_bytes: u64,
    quota_bytes: u64,
) -> Vec<String> {
    // Tuple layout: (artifact_id, last_accessed_unix_ms, footprint_bytes)
    candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let mut evicted = Vec::new();
    for (artifact_id, _last_used, footprint) in candidates {
        if live_bytes <= quota_bytes {
            break;
        }
        evicted.push(artifact_id);
        live_bytes = live_bytes.saturating_sub(footprint);
    }
    evicted
}

/// Summarizes compression efficiency across all active shards in a workspace store.
pub fn summarize_shard_compression(shards: &[ShardDescriptor]) -> (u64, u64, f64) {
    let mut total_raw = 0u64;
    let mut total_compressed = 0u64;
    for s in shards {
        total_raw = total_raw.saturating_add(s.uncompressed_bytes);
        total_compressed = total_compressed.saturating_add(s.compressed_bytes);
    }
    let ratio = if total_raw == 0 {
        0.0
    } else {
        (total_raw as f64 - total_compressed as f64) / (total_raw as f64)
    };
    (total_raw, total_compressed, ratio)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_exceeded_frame_window_and_clamps_eof() {
        let err = verify_frame_window_bounds(0, 65_536, 100_000).unwrap_err();
        assert_eq!(
            err,
            ValidationFault::WindowExceedsCeiling {
                requested_span: 65_536,
                ceiling: MAX_FRAME_WINDOW_BYTES,
            }
        );

        let (s, e, more) = verify_frame_window_bounds(1_000, 5_000, 2_500).unwrap();
        assert_eq!((s, e, more), (1_000, 2_500, false));
    }
}
