//! Deterministic byte-stream encoding classification, lossy line-preserving UTF-8 decoding,
//! and ECMA-48 / VT100 / xterm ANSI escape & carriage-return normalization (`strip_ansi@1`).
//!
//! Original raw bytes remain untouched in `context-store`; this module operates strictly
//! on derived text buffers used for classification, domain reduction, and sanitized previews.

use context_core::StreamEncoding;

/// Known binary file/stream magic byte signatures.
const BINARY_MAGIC_PREFIXES: &[&[u8]] = &[
    b"\x89PNG\r\n\x1a\n", // PNG
    b"\x7fELF",           // ELF
    b"\x28\xb5\x2f\xfd",  // Zstandard frame
    b"\x1f\x8b\x08",      // gzip
    b"PK\x03\x04",        // ZIP / wheel / jar / docx
    b"PK\x05\x06",        // Empty ZIP
    b"\xff\xd8\xff",      // JPEG
    b"GIF87a",            // GIF
    b"GIF89a",            // GIF
    b"%PDF-",             // PDF (binary xref/streams)
    b"SQLite format 3\0", // SQLite DB
    b"\x00asm",           // WebAssembly
    b"MZ\x90\x00",        // Windows PE/COFF
];

/// Outcome of running `strip_ansi@1` over a UTF-8 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsiStripOutcome {
    /// Clean `\n`-normalized UTF-8 text with ANSI escapes and spinner overwrites removed.
    pub text: String,
    /// `true` if any escape sequence, carriage return (`\r` / `\r\n`), or backspace was normalized.
    pub modified: bool,
    /// Count of CSI/OSC/DCS/ESC sequences stripped.
    pub stripped_sequences: usize,
    /// Count of bare `\r` / erase-line progress overwrites resolved.
    pub cr_overwrites: usize,
}

/// Decoded derived text representation of a raw byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedStream {
    /// Detected byte-level encoding (`Utf8`, `Utf8Lossy`, or `Binary`).
    pub encoding: StreamEncoding,
    /// Clean derived text when `encoding != StreamEncoding::Binary` (`None` for binary streams).
    pub normalized_text: Option<String>,
    /// Whether `strip_ansi@1` modified the derived text.
    pub ansi_modified: bool,
    /// Number of ANSI sequences stripped.
    pub stripped_sequences: usize,
    /// Number of bare `\r` progress-bar overwrites collapsed.
    pub cr_overwrites: usize,
}

/// Identifies a human-readable binary format label from leading magic bytes when recognizable.
#[must_use]
pub fn identify_binary_magic(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "PNG image"
    } else if bytes.starts_with(b"\x7fELF") {
        "ELF executable/object"
    } else if bytes.starts_with(b"MZ\x90\x00") || (bytes.starts_with(b"MZ") && bytes.contains(&0)) {
        "PE/COFF Windows binary"
    } else if bytes.starts_with(b"\x28\xb5\x2f\xfd") {
        "Zstandard compressed frame"
    } else if bytes.starts_with(b"\x1f\x8b") {
        "gzip compressed stream"
    } else if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        "ZIP archive"
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        "JPEG image"
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "GIF image"
    } else if bytes.starts_with(b"%PDF-") {
        "PDF document"
    } else if bytes.starts_with(b"SQLite format 3\0") {
        "SQLite database"
    } else if bytes.starts_with(b"\x00asm") {
        "WebAssembly module"
    } else if bytes.contains(&0) {
        "binary stream (contains NUL bytes)"
    } else {
        "non-UTF-8 / binary byte stream"
    }
}

#[inline]
const fn is_disallowed_binary_control(b: u8) -> bool {
    // Allow BEL (0x07), BS (0x08), TAB (0x09), LF (0x0A), VT (0x0B), FF (0x0C), CR (0x0D), ESC (0x1B).
    matches!(b, 0x00..=0x06 | 0x0E..=0x1A | 0x1C..=0x1F | 0x7F)
}

/// Classifies `bytes` into `StreamEncoding::Utf8`, `StreamEncoding::Utf8Lossy`, or
/// `StreamEncoding::Binary`.
///
/// - Any NUL byte (`0x00`) or known binary magic signature immediately classifies as `Binary`.
/// - Valid UTF-8 without excessive binary control bytes classifies as `Utf8`.
/// - Mostly-valid UTF-8 text (`>= 85%` valid text bytes, length `>= 8`, zero NUL bytes) with
///   isolated invalid OEM/ANSI bytes classifies as `Utf8Lossy` so localized tool output does
///   not drop trailing failure lines.
/// - Arbitrary non-UTF-8 byte sequences classify as `Binary`.
#[must_use]
pub fn detect_stream_encoding(bytes: &[u8]) -> StreamEncoding {
    if bytes.is_empty() {
        return StreamEncoding::Utf8;
    }
    if bytes.contains(&0) {
        return StreamEncoding::Binary;
    }
    for sig in BINARY_MAGIC_PREFIXES {
        if bytes.starts_with(sig) {
            return StreamEncoding::Binary;
        }
    }

    if let Ok(valid_str) = std::str::from_utf8(bytes) {
        let bad_ctrl = valid_str
            .as_bytes()
            .iter()
            .filter(|&&b| is_disallowed_binary_control(b))
            .count();
        if bad_ctrl > 0 && bad_ctrl.saturating_mul(20) > bytes.len() {
            return StreamEncoding::Binary;
        }
        return StreamEncoding::Utf8;
    }

    // Invalid UTF-8 without NUL bytes: check whether this is text with isolated OEM bytes
    // vs a binary/non-UTF-8 blob.
    if bytes.len() < 8 {
        return StreamEncoding::Binary;
    }

    let mut valid_text_bytes = 0usize;
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid().as_bytes();
        let clean = valid
            .iter()
            .filter(|&&b| !is_disallowed_binary_control(b))
            .count();
        valid_text_bytes = valid_text_bytes.saturating_add(clean);
    }

    if valid_text_bytes.saturating_mul(100) >= bytes.len().saturating_mul(85) {
        StreamEncoding::Utf8Lossy
    } else {
        StreamEncoding::Binary
    }
}

/// Decodes raw `bytes` into UTF-8 line-by-line by splitting on `b'\n'` and decoding each line
/// with `String::from_utf8_lossy`, guaranteeing that an invalid UTF-8 byte on one line never
/// drops subsequent lines in the stream.
#[must_use]
pub fn decode_lossy_lines(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if let Ok(valid) = std::str::from_utf8(bytes) {
        return valid.to_string();
    }

    let mut out = String::with_capacity(bytes.len());
    let parts: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&String::from_utf8_lossy(part));
    }
    out
}

/// Prepares a raw byte slice for classification and reduction without mutating original bytes.
#[must_use]
pub fn prepare_stream(bytes: &[u8]) -> PreparedStream {
    let encoding = detect_stream_encoding(bytes);
    if encoding == StreamEncoding::Binary {
        return PreparedStream {
            encoding,
            normalized_text: None,
            ansi_modified: false,
            stripped_sequences: 0,
            cr_overwrites: 0,
        };
    }

    let decoded = decode_lossy_lines(bytes);
    let stripped = strip_ansi_and_normalize(&decoded);
    PreparedStream {
        encoding,
        normalized_text: Some(stripped.text),
        ansi_modified: stripped.modified,
        stripped_sequences: stripped.stripped_sequences,
        cr_overwrites: stripped.cr_overwrites,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscState {
    Normal,
    Esc,
    EscIntermediate,
    Csi,
    Osc,
    OscEsc,
    StringSeq,
    StringSeqEsc,
}

/// Strips ECMA-48 / VT100 / xterm escape sequences (CSI colors & private modes, OSC hyperlinks &
/// window titles, DCS/SOS/PM/APC sequences, 8-bit C1 CSI/OSC), resolves `\x08` backspaces and
/// terminal progress-bar `\r` / `\x1b[2K` line overwrites, and normalizes `\r\n` -> `\n`.
#[must_use]
pub fn strip_ansi_and_normalize(input: &str) -> AnsiStripOutcome {
    if input.is_empty() {
        return AnsiStripOutcome {
            text: String::new(),
            modified: false,
            stripped_sequences: 0,
            cr_overwrites: 0,
        };
    }

    let mut stage1 = String::with_capacity(input.len());
    let mut state = EscState::Normal;
    let mut csi_params = String::new();
    let mut stripped_sequences = 0usize;
    let mut modified = false;

    for ch in input.chars() {
        match state {
            EscState::Normal => match ch {
                '\x1b' => {
                    state = EscState::Esc;
                    modified = true;
                }
                '\u{009b}' => {
                    state = EscState::Csi;
                    csi_params.clear();
                    modified = true;
                }
                '\u{009d}' => {
                    state = EscState::Osc;
                    modified = true;
                }
                '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}' => {
                    state = EscState::StringSeq;
                    modified = true;
                }
                '\x07' => {
                    // Stray terminal bell outside OSC.
                    modified = true;
                }
                _ => stage1.push(ch),
            },
            EscState::Esc => match ch {
                '[' => {
                    state = EscState::Csi;
                    csi_params.clear();
                }
                ']' => {
                    state = EscState::Osc;
                }
                'P' | 'X' | '^' | '_' => {
                    state = EscState::StringSeq;
                }
                '\x20'..='\x2f' => {
                    state = EscState::EscIntermediate;
                }
                '\x30'..='\x7e' => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
                '\n' => {
                    stripped_sequences += 1;
                    stage1.push('\n');
                    state = EscState::Normal;
                }
                _ => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
            },
            EscState::EscIntermediate => match ch {
                '\x20'..='\x2f' => {}
                '\x30'..='\x7e' => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
                '\n' => {
                    stripped_sequences += 1;
                    stage1.push('\n');
                    state = EscState::Normal;
                }
                _ => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
            },
            EscState::Csi => match ch {
                '\x30'..='\x3f' => {
                    if csi_params.len() < 32 {
                        csi_params.push(ch);
                    }
                }
                '\x20'..='\x2f' => {}
                '\x40'..='\x7e' => {
                    stripped_sequences += 1;
                    // `\x1b[2K` (Erase entire line) or `\x1b[G` / `\x1b[1G` (Cursor column 1)
                    // is used by `indicatif` / modern progress spinners without `\r` to rewrite
                    // the active terminal line. Emit a synthetic `\r` when current line has text
                    // so the line-overwrite pass resolves the spinner frame cleanly.
                    if ch == 'K' && csi_params == "2" {
                        let has_line_content = stage1
                            .rsplit_once('\n')
                            .map_or(!stage1.is_empty(), |(_, tail)| !tail.is_empty());
                        if has_line_content {
                            stage1.push('\r');
                        }
                    }
                    state = EscState::Normal;
                }
                '\n' => {
                    stripped_sequences += 1;
                    stage1.push('\n');
                    state = EscState::Normal;
                }
                _ => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
            },
            EscState::Osc => match ch {
                '\x07' | '\u{009c}' => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
                '\x1b' => {
                    state = EscState::OscEsc;
                }
                '\n' => {
                    // Safety cap: never allow an unterminated OSC sequence to swallow
                    // subsequent lines of compiler errors or test failures.
                    stripped_sequences += 1;
                    stage1.push('\n');
                    state = EscState::Normal;
                }
                _ => {}
            },
            EscState::OscEsc => {
                stripped_sequences += 1;
                if ch == '\\' {
                    state = EscState::Normal;
                } else if ch == '[' {
                    state = EscState::Csi;
                    csi_params.clear();
                } else if ch == ']' {
                    state = EscState::Osc;
                } else {
                    if ch == '\n' {
                        stage1.push('\n');
                    }
                    state = EscState::Normal;
                }
            }
            EscState::StringSeq => match ch {
                '\x07' | '\u{009c}' => {
                    stripped_sequences += 1;
                    state = EscState::Normal;
                }
                '\x1b' => {
                    state = EscState::StringSeqEsc;
                }
                '\n' => {
                    stripped_sequences += 1;
                    stage1.push('\n');
                    state = EscState::Normal;
                }
                _ => {}
            },
            EscState::StringSeqEsc => {
                stripped_sequences += 1;
                if ch == '\\' {
                    state = EscState::Normal;
                } else {
                    if ch == '\n' {
                        stage1.push('\n');
                    }
                    state = EscState::Normal;
                }
            }
        }
    }

    if state != EscState::Normal {
        stripped_sequences += 1;
    }

    // Fast path if neither `\r` nor `\x08` appears in stage1.
    if !stage1.contains('\r') && !stage1.contains('\x08') {
        return AnsiStripOutcome {
            text: stage1,
            modified,
            stripped_sequences,
            cr_overwrites: 0,
        };
    }

    // Normalize `\r\n` -> `\n` first.
    let lf_normalized = if stage1.contains("\r\n") {
        modified = true;
        stage1.replace("\r\n", "\n")
    } else {
        stage1
    };

    let mut cr_overwrites = 0usize;
    let mut resolved = String::with_capacity(lf_normalized.len());

    let raw_lines: Vec<&str> = lf_normalized.split('\n').collect();
    for (idx, raw_line) in raw_lines.iter().enumerate() {
        if idx > 0 {
            resolved.push('\n');
        }

        let trimmed_trailing_cr = raw_line.trim_end_matches('\r');
        if trimmed_trailing_cr.len() < raw_line.len() {
            modified = true;
        }

        let active_segment = if trimmed_trailing_cr.contains('\r') {
            modified = true;
            // Count bare `\r` overwrites and keep the last non-empty segment (or empty if
            // the overwrite explicitly cleared the line via `\x1b[2K` -> `\r`).
            let segments: Vec<&str> = trimmed_trailing_cr.split('\r').collect();
            cr_overwrites += segments.len().saturating_sub(1);
            segments
                .iter()
                .rev()
                .copied()
                .find(|seg| !seg.is_empty())
                .unwrap_or("")
        } else {
            trimmed_trailing_cr
        };

        if active_segment.contains('\x08') {
            modified = true;
            let mut line_chars: Vec<char> = Vec::with_capacity(active_segment.len());
            for ch in active_segment.chars() {
                if ch == '\x08' {
                    line_chars.pop();
                } else {
                    line_chars.push(ch);
                }
            }
            for ch in line_chars {
                resolved.push(ch);
            }
        } else {
            resolved.push_str(active_segment);
        }
    }

    AnsiStripOutcome {
        text: resolved,
        modified,
        stripped_sequences,
        cr_overwrites,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_osc8_hyperlinks_dcs_and_spinners() {
        let raw = concat!(
            "\x1b[?25l\x1b[?2004h",
            "  Downloading foo v0.1.0\r  Downloading bar v0.2.0\r",
            "\x1b[32;1m   Finished\x1b[0m `test` profile\r\n",
            "\x1b]8;;file:///repo/src/lib.rs\x07src/lib.rs:42:9\x1b]8;;\x07\r\n",
            "\x1b]8;id=99;https://docs.rs\x1b\\error[E0308]\x1b]8;;\x1b\\\r\n",
            "\x1bP1$r0m\x1b\\done\x1b[?25h"
        );
        let out = strip_ansi_and_normalize(raw);
        assert!(out.modified);
        assert!(out.stripped_sequences >= 6);
        assert_eq!(out.cr_overwrites, 2);
        assert_eq!(
            out.text,
            "   Finished `test` profile\nsrc/lib.rs:42:9\nerror[E0308]\ndone"
        );
    }

    #[test]
    fn handles_indicatif_erase_line_and_backspaces() {
        let raw = "Frame 1\x1b[2K\x1b[1GFrame 2\x1b[2K\x1b[1GFinal\nab\x08c\n";
        let out = strip_ansi_and_normalize(raw);
        assert_eq!(out.text, "Final\nac\n");
    }

    #[test]
    fn lossy_decoding_never_drops_lines_after_invalid_utf8_byte() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"running 2 tests\ntest first_oem_quote ");
        bytes.push(0x93); // Windows-1252 smart quote byte (invalid standalone UTF-8)
        bytes.extend_from_slice(b" ... ok\ntest critical_auth_check ... FAILED\n");

        assert_eq!(detect_stream_encoding(&bytes), StreamEncoding::Utf8Lossy);
        let prep = prepare_stream(&bytes);
        let text = prep.normalized_text.expect("lossy text");
        assert!(text.contains("test critical_auth_check ... FAILED"));
    }
}
