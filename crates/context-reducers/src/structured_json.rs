//! Deterministic structured JSON / concatenated-JSON / NDJSON reducer (`structured_json@1`),
//! backed by the `user-rust-anything`-gated `ported` engine (`Apache-2.0` Headroom port).
//!
//! Preserves error/status/count keys, array lengths, homogeneous record schema shapes,
//! representative elements, and embedded error records while omitting repetitive bulk items.

use context_core::{ArtifactId, ReductionBudget, StreamKind, ViewKind};
use serde_json::Value;

use crate::common::{
    count_lines, dedup_preserve_order, format_recovery_hint, DomainReduction, RecoveryRange,
};
use crate::ported::{
    extract_bulk_json, is_error_item, loads_strict, normalize_concatenated_json,
    render_node_with_stats, RenderSummaryStats, ERROR_BEARING_KEYS,
};

fn collect_json_error_identifiers(root: &Value, out: &mut Vec<String>) {
    match root {
        Value::Object(map) => {
            if is_error_item(root) {
                for &k in ERROR_BEARING_KEYS {
                    if let Some(v) = map.get(k) {
                        match v {
                            Value::String(s) if !s.trim().is_empty() => {
                                out.push(format!("{k}: {}", s.trim()));
                            }
                            Value::Array(arr) => {
                                for elem in arr.iter().take(10) {
                                    if let Some(s) = elem.as_str() {
                                        out.push(format!("{k}: {}", s.trim()));
                                    } else if let Some(obj) = elem.as_object() {
                                        if let Some(msg) = obj
                                            .get("message")
                                            .or_else(|| obj.get("code"))
                                            .and_then(Value::as_str)
                                        {
                                            out.push(format!("{k}: {}", msg.trim()));
                                        }
                                    }
                                }
                            }
                            Value::Object(err_obj) => {
                                if let Some(msg) = err_obj
                                    .get("message")
                                    .or_else(|| err_obj.get("code"))
                                    .and_then(Value::as_str)
                                {
                                    out.push(format!("{k}: {}", msg.trim()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if out.is_empty() {
                    if let Some(msg) = map
                        .get("message")
                        .or_else(|| map.get("reason"))
                        .and_then(Value::as_str)
                    {
                        out.push(msg.trim().to_string());
                    }
                }
            }
            for val in map.values() {
                if let Value::Array(arr) = val {
                    for (idx, item) in arr.iter().enumerate() {
                        if is_error_item(item) {
                            if let Some(obj) = item.as_object() {
                                let label = obj
                                    .get("error")
                                    .or_else(|| obj.get("fatal"))
                                    .or_else(|| obj.get("message"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("error_record");
                                out.push(format!("item[{idx}]: {label}"));
                            }
                        }
                    }
                }
            }
        }
        Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                if is_error_item(item) {
                    if let Some(obj) = item.as_object() {
                        let label = obj
                            .get("error")
                            .or_else(|| obj.get("fatal"))
                            .or_else(|| obj.get("message"))
                            .and_then(Value::as_str)
                            .unwrap_or("error_record");
                        out.push(format!("item[{idx}]: {label}"));
                    }
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn reduce_structured_json(
    text: &str,
    stream: StreamKind,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> Result<DomainReduction, String> {
    let Some(detected) = extract_bulk_json(text) else {
        return Err("input does not contain valid bulk JSON object or array".to_string());
    };

    let normalized_concat;
    let json_target = if detected.is_concatenated {
        normalized_concat = normalize_concatenated_json(detected.json_slice);
        if normalized_concat.is_empty() {
            return Err("failed to normalize concatenated JSON stream".to_string());
        }
        normalized_concat.as_str()
    } else {
        detected.json_slice
    };

    let Some(parsed) = loads_strict(json_target) else {
        return Err("strict RFC 8259 JSON parse failed or exceeded nesting depth".to_string());
    };

    let mut raw_errors: Vec<String> = Vec::new();
    collect_json_error_identifiers(&parsed, &mut raw_errors);
    let failure_identifiers = dedup_preserve_order(raw_errors);

    let mut stats = RenderSummaryStats {
        omitted_items: 0,
        omitted_keys: 0,
        truncated_depth: false,
    };
    let structural = render_node_with_stats(&parsed, 0, 4, 3, true, &mut stats);
    let was_compacted = stats.omitted_items > 0 || stats.omitted_keys > 0 || stats.truncated_depth;

    // Never-worse check: if small JSON had zero elided items/keys/depth and sanitized raw text
    // is already smaller than the structural summary (and within budget), keep the concise raw text!
    let trimmed_raw = text.trim();
    if !was_compacted
        && trimmed_raw.len() <= structural.len()
        && trimmed_raw.len() <= budget.max_view_bytes
        && count_lines(trimmed_raw) <= budget.max_view_lines
    {
        return Ok(DomainReduction {
            kind: ViewKind::StructuredJson,
            safe_excerpt: trimmed_raw.to_string(),
            omitted: false,
            failure_identifiers,
        });
    }

    let mut out_lines: Vec<String> = Vec::new();
    let kind_label = if detected.is_concatenated {
        "ndjson/concatenated_json"
    } else {
        detected.kind
    };
    out_lines.push(format!("structured_json@1 ({kind_label}):"));
    if !detected.prefix.is_empty() {
        let prefix_first = detected.prefix.lines().next().unwrap_or("");
        if !prefix_first.is_empty() {
            out_lines.push(format!("preamble: {prefix_first}"));
        }
    }
    out_lines.push(structural);

    let total_lines = count_lines(text);
    let omitted =
        was_compacted || total_lines > out_lines.len() || text.len() > budget.max_view_bytes;
    if omitted {
        let range = if total_lines > 1 {
            RecoveryRange::Lines {
                start: 1,
                end: total_lines.min(budget.max_get_lines),
            }
        } else {
            RecoveryRange::Bytes {
                start: 0,
                end: (text.len() as u64).min(budget.max_get_bytes as u64),
            }
        };
        out_lines.push(format!(
            "omitted: {} byte(s) / {total_lines} line(s) | {}",
            text.len(),
            format_recovery_hint(artifact_id, originals_available, stream, range)
        ));
    }

    Ok(DomainReduction {
        kind: ViewKind::StructuredJson,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    })
}
