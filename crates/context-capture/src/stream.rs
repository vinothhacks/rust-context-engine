//! Bounded byte stream accumulators, cancellation primitives, and encoding helpers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use context_core::{sha256_hex, StreamEncoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Notify;

const READ_CHUNK_SIZE: usize = 8 * 1024;

/// Cooperative cancellation token for aborting in-flight command or file captures cleanly.
#[derive(Debug, Clone, Default)]
pub struct CaptureCancelToken {
    inner: Arc<CancelInner>,
}

#[derive(Debug, Default)]
struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CaptureCancelToken {
    /// Creates an uncancelled [`CaptureCancelToken`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Signals cancellation to all active waiters.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Returns `true` if cancellation has been triggered.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves as soon as [`Self::cancel`] has been called.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Exact raw captured stream (`stdout`, `stderr`, or `document`) with integrity and truncation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedStream {
    /// Raw bytes retained in memory up to `max_capture_bytes_per_stream`.
    pub bytes: Vec<u8>,
    /// Total bytes observed on the underlying pipe/file (may exceed `bytes.len()` when truncated).
    pub observed_bytes: u64,
    /// Lowercase SHA-256 hex digest of `bytes` (matches blob persisted in `context-store`).
    pub sha256: String,
    /// Lowercase SHA-256 hex digest over all `observed_bytes` read from the source.
    pub observed_sha256: String,
    /// `true` if `observed_bytes` exceeded the capture cap and trailing bytes were discarded.
    pub truncated: bool,
    /// Detected byte-level encoding (`utf-8` or `binary`) of `bytes`.
    pub encoding: StreamEncoding,
    /// Optional non-fatal stream read error message if the pipe closed abnormally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

impl CapturedStream {
    /// Number of bytes retained in `self.bytes`.
    #[must_use]
    pub fn captured_len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Builds a [`CapturedStream`] directly from an in-memory byte slice bounded to `max_bytes`.
    #[must_use]
    pub fn from_slice_bounded(raw: &[u8], max_bytes: u64) -> Self {
        let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        let truncated = raw.len() > cap;
        let kept = if truncated { &raw[..cap] } else { raw };
        let sha256 = sha256_hex(kept);
        let observed_sha256 = if truncated {
            sha256_hex(raw)
        } else {
            sha256.clone()
        };
        let encoding = StreamEncoding::detect(kept);

        Self {
            bytes: kept.to_vec(),
            observed_bytes: raw.len() as u64,
            sha256,
            observed_sha256,
            truncated,
            encoding,
            read_error: None,
        }
    }
}

pub(crate) struct StreamAccumulator {
    bytes: Vec<u8>,
    observed_bytes: u64,
    observed_hasher: Sha256,
    truncated: bool,
    max_bytes: usize,
    read_error: Option<String>,
}

impl StreamAccumulator {
    pub(crate) fn new(max_bytes: u64) -> Self {
        let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        Self {
            bytes: Vec::with_capacity(cap.min(16 * 1024)),
            observed_bytes: 0,
            observed_hasher: Sha256::new(),
            truncated: false,
            max_bytes: cap,
            read_error: None,
        }
    }

    pub(crate) fn push_chunk(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.observed_bytes = self.observed_bytes.saturating_add(chunk.len() as u64);
        self.observed_hasher.update(chunk);

        let remaining = self.max_bytes.saturating_sub(self.bytes.len());
        if remaining >= chunk.len() {
            self.bytes.extend_from_slice(chunk);
        } else {
            if remaining > 0 {
                self.bytes.extend_from_slice(&chunk[..remaining]);
            }
            self.truncated = true;
        }
    }

    pub(crate) fn peek_read_error(&self) -> Option<&str> {
        self.read_error.as_deref()
    }

    pub(crate) fn finalize(self) -> CapturedStream {
        let observed_sha256 = hex::encode(self.observed_hasher.finalize());
        let sha256 = if !self.truncated {
            observed_sha256.clone()
        } else {
            sha256_hex(&self.bytes)
        };
        let encoding = StreamEncoding::detect(&self.bytes);

        CapturedStream {
            bytes: self.bytes,
            observed_bytes: self.observed_bytes,
            sha256,
            observed_sha256,
            truncated: self.truncated,
            encoding,
            read_error: self.read_error,
        }
    }
}

pub(crate) async fn read_stream_bounded<R>(mut reader: R, acc: &mut StreamAccumulator)
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0u8; READ_CHUNK_SIZE];
    loop {
        match reader.read(&mut scratch).await {
            Ok(0) => break,
            Ok(n) => acc.push_chunk(&scratch[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                acc.read_error = Some(err.to_string());
                break;
            }
        }
    }
}

/// Combines encodings from `stdout` and `stderr` into a single summary encoding.
#[must_use]
pub const fn combine_stream_encodings(a: StreamEncoding, b: StreamEncoding) -> StreamEncoding {
    match (a, b) {
        (StreamEncoding::Binary, _) | (_, StreamEncoding::Binary) => StreamEncoding::Binary,
        (StreamEncoding::Utf8Lossy, _) | (_, StreamEncoding::Utf8Lossy) => {
            StreamEncoding::Utf8Lossy
        }
        (StreamEncoding::Utf8, StreamEncoding::Utf8) => StreamEncoding::Utf8,
    }
}
