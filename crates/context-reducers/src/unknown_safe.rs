//! Safe bounded fallback reducer (`unknown_safe@1`) for binary, malformed/non-UTF-8,
//! unrecognized text, and fail-safe reducer error degradation.
//!
//! Always reports byte count, SHA-256 digest, `StreamEncoding`, safe bounded preview
//! (UTF-8 / lossy head+tail for text when non-secret; magic format + hex summary for binary),
//! explicit `omitted` status, and exact `context_get` byte/line recovery guidance.

use context_core::{
    sha256_hex, truncate_str_utf8_boundary, ArtifactId, ReductionBudget, StreamEncoding,
    StreamKind, ViewKind,
};

use crate::ansi::identify_binary_magic;
use crate::common::{
    count_lines, format_exit_badge, format_recovery_hint, DomainReduction, RecoveryRange,
};

pub(crate) struct UnknownSafeParams<'a> {
    pub view_kind: ViewKind,
    pub stream: StreamKind,
    pub raw_bytes: &'a [u8],
    pub secondary_stderr_bytes: Option<&'a [u8]>,
    pub encoding: StreamEncoding,
    pub sanitized_text: Option<&'a str>,
    pub secrets_detected_in_binary: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub capture_truncated: bool,
    pub artifact_id: Option<&'a ArtifactId>,
    pub originals_available: bool,
    pub reduction_error_note: Option<&'a str>,
    pub budget: &'a ReductionBudget,
}

fn format_hex_head(bytes: &[u8], max_bytes: usize) -> String {
    let take = bytes.len().min(max_bytes);
    bytes[..take]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

fn build_head_tail_preview(
    text: &str,
    max_preview_bytes: usize,
    max_lines: usize,
) -> (String, bool) {
    if text.is_empty() {
        return (String::new(), false);
    }

    let lines: Vec<&str> = text.lines().collect();
    if text.len() <= max_preview_bytes && lines.len() <= max_lines {
        return (text.to_string(), false);
    }

    // Split preview budget ~65% head, ~35% tail so both start headers and final outcomes remain visible.
    let marker_reserve = 48usize;
    let usable = max_preview_bytes.saturating_sub(marker_reserve).max(16);
    let head_budget = (usable * 13) / 20;
    let tail_budget = usable.saturating_sub(head_budget).max(8);

    let head_line_cap = ((max_lines * 3) / 5).max(1);
    let tail_line_cap = max_lines.saturating_sub(head_line_cap + 1).max(1);

    if lines.len() > 2 && head_line_cap + tail_line_cap < lines.len() {
        let head_joined = lines[..head_line_cap].join("\n");
        let tail_joined = lines[lines.len() - tail_line_cap..].join("\n");
        let (head_slice, _) = truncate_str_utf8_boundary(&head_joined, head_budget);
        let (tail_slice, _) = truncate_str_utf8_boundary(&tail_joined, tail_budget);
        let omitted_lines = lines.len().saturating_sub(head_line_cap + tail_line_cap);
        return (
            format!("{head_slice}\n... [{omitted_lines} line(s) omitted] ...\n{tail_slice}"),
            true,
        );
    }

    let (head_slice, _) = truncate_str_utf8_boundary(text, head_budget);
    // Walk forward from `text.len() - tail_budget` to a valid UTF-8 boundary.
    let mut tail_start = text.len().saturating_sub(tail_budget);
    while tail_start < text.len() && !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let tail_slice = &text[tail_start..];
    if tail_start <= head_slice.len() {
        let (single, cut) = truncate_str_utf8_boundary(text, max_preview_bytes);
        return (single.to_string(), cut);
    }
    let omitted_bytes = tail_start.saturating_sub(head_slice.len());
    (
        format!("{head_slice}\n... [{omitted_bytes} byte(s) omitted] ...\n{tail_slice}"),
        true,
    )
}

pub(crate) fn reduce_unknown_safe(params: &UnknownSafeParams<'_>) -> DomainReduction {
    let primary_sha = sha256_hex(params.raw_bytes);
    let primary_len = params.raw_bytes.len();
    let total_len = primary_len + params.secondary_stderr_bytes.map_or(0, <[u8]>::len);

    let mut out_lines: Vec<String> = Vec::new();
    let exit_part = if params.exit_code.is_some() || params.timed_out {
        format!(
            " ({})",
            format_exit_badge(params.exit_code, params.timed_out)
        )
    } else {
        String::new()
    };

    out_lines.push(format!(
        "unknown_safe@1{exit_part}: bytes={total_len} encoding={} sha256={primary_sha}",
        params.encoding.as_str()
    ));

    if let Some(sec_bytes) = params.secondary_stderr_bytes {
        if !sec_bytes.is_empty() {
            out_lines.push(format!(
                "stderr_stream: bytes={} sha256={}",
                sec_bytes.len(),
                sha256_hex(sec_bytes)
            ));
        }
    }

    if let Some(err_note) = params.reduction_error_note {
        out_lines.push(format!("degraded_fallback: {err_note}"));
    }

    if params.encoding == StreamEncoding::Binary {
        let magic = identify_binary_magic(params.raw_bytes);
        out_lines.push(format!(
            "binary_format: {magic} (unparsed binary/non-UTF-8 payload)"
        ));
        if params.secrets_detected_in_binary {
            out_lines.push("hex_head: [withheld: embedded secret pattern detected]".to_string());
        } else if !params.raw_bytes.is_empty() {
            out_lines.push(format!(
                "hex_head({}B): {}",
                params.raw_bytes.len().min(24),
                format_hex_head(params.raw_bytes, 24)
            ));
        }
        let omitted = total_len > 0 || params.capture_truncated;
        if omitted {
            let end_byte = (primary_len as u64).min(params.budget.max_get_bytes as u64);
            out_lines.push(format_recovery_hint(
                params.artifact_id,
                params.originals_available,
                params.stream,
                RecoveryRange::Bytes {
                    start: 0,
                    end: end_byte,
                },
            ));
        }
        return DomainReduction {
            kind: ViewKind::UnknownSafe,
            safe_excerpt: out_lines.join("\n"),
            omitted,
            failure_identifiers: Vec::new(),
        };
    }

    // Text (`Utf8` or `Utf8Lossy`) preview path
    if params.encoding == StreamEncoding::Utf8Lossy {
        out_lines.push(
            "format_uncertainty: stream contained non-UTF-8 byte(s); preview decoded lossily"
                .to_string(),
        );
    }

    let text = params.sanitized_text.unwrap_or("");
    let preview_line_budget = params.budget.max_view_lines.saturating_sub(6).max(4);
    let (preview, preview_truncated) =
        build_head_tail_preview(text, params.budget.max_preview_bytes, preview_line_budget);

    if !preview.is_empty() {
        out_lines.push("preview:".to_string());
        out_lines.push(preview);
    }

    let omitted = preview_truncated
        || params.capture_truncated
        || params.encoding == StreamEncoding::Utf8Lossy
        || params.reduction_error_note.is_some();

    if omitted && total_len > 0 {
        let range = if params.encoding == StreamEncoding::Utf8Lossy {
            RecoveryRange::Bytes {
                start: 0,
                end: (primary_len as u64).min(params.budget.max_get_bytes as u64),
            }
        } else {
            let total_lines = count_lines(text).max(1);
            RecoveryRange::Lines {
                start: 1,
                end: total_lines.min(params.budget.max_get_lines),
            }
        };
        out_lines.push(format_recovery_hint(
            params.artifact_id,
            params.originals_available,
            params.stream,
            range,
        ));
    }

    DomainReduction {
        kind: params.view_kind,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers: Vec::new(),
    }
}
