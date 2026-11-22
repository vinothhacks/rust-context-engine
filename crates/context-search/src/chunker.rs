//! Line-addressed UTF-8 text chunking and hostile-input FTS5 query sanitization.

use std::sync::LazyLock;

use context_core::truncate_str_utf8_boundary;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Maximum number of lexical tokens emitted into a sanitized FTS5 `MATCH` expression.
const MAX_QUERY_TOKENS: usize = 32;

/// Maximum UTF-8 byte length of a single query token passed to FTS5.
const MAX_QUERY_TOKEN_BYTES: usize = 128;

static WORD_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\p{L}\p{N}_]+").expect("valid Unicode word token regex"));

/// Controls line-window sizing when splitting sanitized streams into FTS5 chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkConfig {
    /// Maximum lines grouped into a single chunk (`40` default; must fit `ReductionBudget::max_get_lines`).
    pub max_lines_per_chunk: usize,
    /// Maximum UTF-8 bytes per chunk (`4_096` default) so minified single-line logs stay bounded.
    pub max_bytes_per_chunk: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            max_lines_per_chunk: 40,
            max_bytes_per_chunk: 4_096,
        }
    }
}

/// Single 1-indexed inclusive line-addressed chunk ready for FTS5 insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextChunk {
    pub chunk_seq: usize,
    pub line_start: usize,
    pub line_end: usize,
    pub body: String,
}

/// Splits `sanitized_text` into deterministic 1-indexed inclusive `(line_start..=line_end)` chunks.
///
/// - Empty or whitespace-only inputs yield an empty `Vec` so empty strings do not pollute FTS5.
/// - Oversized single lines (`> max_bytes_per_chunk`) are split safely on UTF-8 character
///   boundaries while retaining their exact 1-indexed line number (`line_start == line_end`).
#[must_use]
pub fn chunk_sanitized_text(sanitized_text: &str, cfg: ChunkConfig) -> Vec<TextChunk> {
    if sanitized_text.trim().is_empty() {
        return Vec::new();
    }

    let max_lines = cfg.max_lines_per_chunk.max(1);
    let max_bytes = cfg.max_bytes_per_chunk.max(64);

    let mut chunks: Vec<TextChunk> = Vec::new();
    let mut current_body = String::new();
    let mut current_start_line = 0usize;
    let mut current_end_line = 0usize;
    let mut current_line_count = 0usize;

    let flush_current = |chunks: &mut Vec<TextChunk>,
                         body: &mut String,
                         start_line: &mut usize,
                         end_line: &mut usize,
                         line_count: &mut usize| {
        if !body.trim().is_empty() && *start_line >= 1 {
            let seq = chunks.len();
            chunks.push(TextChunk {
                chunk_seq: seq,
                line_start: *start_line,
                line_end: (*end_line).max(*start_line),
                body: std::mem::take(body),
            });
        } else {
            body.clear();
        }
        *start_line = 0;
        *end_line = 0;
        *line_count = 0;
    };

    for (idx, raw_line) in sanitized_text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        // Handle oversized single lines (e.g. minified JSON) without losing line provenance.
        if line.len() > max_bytes {
            flush_current(
                &mut chunks,
                &mut current_body,
                &mut current_start_line,
                &mut current_end_line,
                &mut current_line_count,
            );

            let mut remaining = line;
            while !remaining.is_empty() {
                let (piece, _) = truncate_str_utf8_boundary(remaining, max_bytes);
                if piece.is_empty() {
                    break;
                }
                if !piece.trim().is_empty() {
                    let seq = chunks.len();
                    chunks.push(TextChunk {
                        chunk_seq: seq,
                        line_start: line_no,
                        line_end: line_no,
                        body: piece.to_string(),
                    });
                }
                remaining = &remaining[piece.len()..];
            }
            continue;
        }

        let sep_len = usize::from(!current_body.is_empty());
        let would_exceed_lines = current_line_count >= max_lines;
        let would_exceed_bytes =
            !current_body.is_empty() && (current_body.len() + sep_len + line.len() > max_bytes);

        if would_exceed_lines || would_exceed_bytes {
            flush_current(
                &mut chunks,
                &mut current_body,
                &mut current_start_line,
                &mut current_end_line,
                &mut current_line_count,
            );
        }

        if current_start_line == 0 {
            current_start_line = line_no;
        }
        if !current_body.is_empty() {
            current_body.push('\n');
        }
        current_body.push_str(line);
        current_end_line = line_no;
        current_line_count += 1;
    }

    flush_current(
        &mut chunks,
        &mut current_body,
        &mut current_start_line,
        &mut current_end_line,
        &mut current_line_count,
    );

    chunks
}

/// Converts arbitrary untrusted user query input into a syntax-error-proof SQLite FTS5 `MATCH`
/// expression.
///
/// Every extracted Unicode word/identifier token (`[\p{L}\p{N}_]+`) is wrapped in double quotes
/// (`"token"`), neutralizing FTS5 column-filter syntax (`col:val`), unbalanced quotes, wildcards,
/// parentheses, NUL bytes, boolean/NEAR operators (`AND`, `OR`, `NOT`, `NEAR`), and SQL/FTS
/// injection payloads.
///
/// Returns `None` when `raw_query` contains zero searchable alphanumeric/underscore tokens.
#[must_use]
pub fn sanitize_fts5_query(raw_query: &str) -> Option<String> {
    let mut quoted_tokens: Vec<String> = Vec::new();

    for mat in WORD_TOKEN_RE.find_iter(raw_query) {
        let raw_tok = mat.as_str();
        // Strip underscores-only tokens (`___`) that carry zero lexical tokens under unicode61.
        if raw_tok.bytes().all(|b| b == b'_') {
            continue;
        }

        let (bounded_tok, _) = truncate_str_utf8_boundary(raw_tok, MAX_QUERY_TOKEN_BYTES);
        if bounded_tok.is_empty() || bounded_tok.bytes().all(|b| b == b'_') {
            continue;
        }

        // `WORD_TOKEN_RE` guarantees no `"` or NUL exists in `bounded_tok`, so `"..."` is
        // unconditionally a valid FTS5 phrase literal.
        let quoted = format!("\"{bounded_tok}\"");
        if !quoted_tokens.iter().any(|existing| existing == &quoted) {
            quoted_tokens.push(quoted);
        }

        if quoted_tokens.len() >= MAX_QUERY_TOKENS {
            break;
        }
    }

    if quoted_tokens.is_empty() {
        None
    } else {
        Some(quoted_tokens.join(" "))
    }
}
