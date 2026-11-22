// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Headroom Contributors
//
// Verified Rust port of `headroom_port/classifier_json_reducer.py`, adapted from
// `chopratejas/headroom` @ commit `ce0460cfa8598dc939243dbc7aec4b2d35f4e44a`
// (`headroom/transforms/content_detector.py`, `headroom/transforms/lossless_compaction.py`,
// and `headroom/transforms/recursive_json.py`) under the Apache License, Version 2.0.
//
// Differential Verification Summary (`user-rust-anything` MCP v3.1.0):
// - `diff`:   1180 / 1180 recorded cases matched (0 mismatches, 138 Unicode/BOM/numeric traps)
// - `fuzz`:   2748 / 2748 fresh cases matched (`seed = 20261122`, 2 rounds, 0 mismatches)
// - `bench`:  6.94x - 7.19x geometric mean speedup (FFI call included; up to 17.05x per fn)
// - `gate`:   PASSED (12 / 12 checks: fmt, clippy -D warnings, cargo test, forbid(unsafe_code),
//             lockfile, ported, size, error cases, panics, build, api, behavior)

//! Pure-Rust deterministic content classifier and structured JSON reducer (`port.rs`).
//! Ready for integration into `crates/context-reducers` (`structured_json@1` and `Classifier`).

#![forbid(unsafe_code)]

use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

const SCAN_BUDGET_PER_CHAR: usize = 4;
const SCAN_BUDGET_FLOOR: usize = 4096;
const MAX_JSON_DEPTH: usize = 64;

const PRIORITY_KEYS: &[&str] = &[
    "code",
    "error",
    "errors",
    "exit_code",
    "fatal",
    "message",
    "ok",
    "reason",
    "status",
    "success",
    "traceback",
    "warnings",
];

const ERROR_BEARING_KEYS: &[&str] = &["error", "errors", "fatal", "traceback"];

const GIT_STATUS_HEADERS: &[&str] = &[
    "Changes to be committed:",
    "Changes not staged for commit:",
    "Untracked files:",
    "Unmerged paths:",
];

const WS_CHARS: &[char] = &[' ', '\t', '\n', '\r'];

static TIMESTAMP_ROW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        concat!(
            r"^[\t-\r ]*\[?(?:",
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{1,2}:[0-9]{2}",
            r"|[0-9]{4}/[0-9]{2}/[0-9]{2}[ T][0-9]{1,2}:[0-9]{2}",
            r"|[0-9]{2}/[0-9]{2}/[0-9]{2,4}[ T][0-9]{1,2}:[0-9]{2}",
            r"|[A-Z][a-z]{2}[\t-\r ]+[0-9]{1,2}[\t-\r ]+[0-9]{1,2}:[0-9]{2}",
            r"|[IWEF][0-9]{4}[\t-\r ]+[0-9]{1,2}:[0-9]{2}",
            r"|[DIWEFA], \[[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}",
            r"|[A-Za-z0-9_.-]{1,255} [^\t-\r :]+ [^\t-\r :]+ \[[0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}",
            r"|[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?(?:[\t-\r ]|\]|\z)",
            r")",
        ),
    )
    .expect("valid TIMESTAMP_ROW_RE")
});

static DIFF_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        concat!(
            r"^(?:",
            r"diff --git",
            r"|diff --combined ",
            r"|diff --cc ",
            r"|--- a/",
            r"|@@[\t-\r ]+-[0-9]+(?:,[0-9]+)?[\t-\r ]+\+[0-9]+(?:,[0-9]+)?[\t-\r ]+@@",
            r"|@@@+[\t-\r ]+-[0-9]+(?:,[0-9]+)?[\t-\r ]+(?:-[0-9]+(?:,[0-9]+)?[\t-\r ]+)+\+[0-9]+(?:,[0-9]+)?[\t-\r ]+@@@+",
            r")",
        ),
    )
    .expect("valid DIFF_HEADER_RE")
});

static HTML_DOCTYPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[\t-\r ]*(?i-u:<!doctype)[\t-\r ]+(?i-u:html)").expect("valid HTML_DOCTYPE_RE")
});
static HTML_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:<html)[\t-\r >]").expect("valid HTML_TAG_RE"));
static HTML_HEAD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:<head)[\t-\r >]").expect("valid HTML_HEAD_RE"));
static HTML_BODY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:<body)[\t-\r >]").expect("valid HTML_BODY_RE"));
static HTML_STRUCTURAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u:<(?:div|span|script|style|link|meta|nav|header|footer|aside|article|section|main))[\t-\r >]")
        .expect("valid HTML_STRUCTURAL_RE")
});

static GIT_STATUS_ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[\t-\r ]+(?:new file|modified|deleted|renamed|copied|typechange|both modified|both added|both deleted|added by us|deleted by us|added by them|deleted by them):[\t-\r ]+[^\t-\r ]",
    )
    .expect("valid GIT_STATUS_ENTRY_RE")
});

static MD_SEP_CELL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^:?-{2,}:?\z").expect("valid MD_SEP_CELL_RE"));
static FIXED_WIDTH_LIST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[ \t]*(?:[-*+\u{2022}]|[0-9]{1,3}[.)])[ \t]").expect("valid FIXED_WIDTH_LIST_RE")
});

static LOG_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let raw = [
        r"(?-u:\b)(?i-u:ERROR|FAIL|FAILED|FATAL|CRITICAL)(?-u:\b)",
        r"(?-u:\b)(?i-u:WARN|WARNING)(?-u:\b)",
        r"(?-u:\b)(?i-u:INFO|DEBUG|TRACE)(?-u:\b)",
        r"^[\t-\r ]*[0-9]{4}-[0-9]{2}-[0-9]{2}",
        r"^[\t-\r ]*\[[0-9]{2}:[0-9]{2}:[0-9]{2}\]",
        r"^={3,}|^-{3,}",
        r"^[\t-\r ]*PASSED|^[\t-\r ]*FAILED|^[\t-\r ]*SKIPPED",
        r"^npm ERR!|^yarn error|^cargo error|^error\[E[0-9]+\]:|^test result:",
        r"Traceback \(most recent call last\)",
        r"^[A-Za-z0-9_]*(?:Error|Exception):",
        r"^[\t-\r ]*at[\t-\r ]+[A-Za-z0-9_.$/]+\(",
        r"^[\t-\r ]*at async [^\t-\r ]",
        r"^(?:panic|fatal error): ",
        r"^goroutine [0-9]+ \[",
        r"^\t[^\t-\r ]+\.go:[0-9]+ \+0x",
        r"^thread '[^']*' panicked at",
        r"^stack backtrace:",
        r"^[\t-\r ]+[0-9]+: [^\t-\r ]",
        r"^[\t-\r ]+at [^\t-\r ]+:[0-9]+:[0-9]+\z",
        r"^Unhandled exception\.",
        r"^[\t-\r ]*at .+\) in .+:line [0-9]+",
        r"^Caused by: ",
        r"^[\t-\r ]*\.\.\. [0-9]+ more\z",
        r"^<!\[LOG\[",
    ];
    raw.into_iter()
        .map(|pat| Regex::new(pat).expect("valid log regex"))
        .collect()
});

static CODE_PATTERNS: LazyLock<Vec<Vec<Regex>>> = LazyLock::new(|| {
    let groups: &[&[&str]] = &[
        // python
        &[
            r"^[\t-\r ]*(?:def|class|import|from|async def)[\t-\r ]+[A-Za-z0-9_]+",
            r"^[\t-\r ]*@[A-Za-z0-9_]+",
            r#"^[\t-\r ]*""""#,
            r"^[\t-\r ]*if __name__[\t-\r ]*==",
        ],
        // javascript
        &[
            r"^[\t-\r ]*(?:function|const|let|var|class|import|export)[\t-\r ]+",
            r"^[\t-\r ]*(?:async[\t-\r ]+function|=>[\t-\r ]*\{)",
            r"^[\t-\r ]*module\.exports",
        ],
        // typescript (anchored at index 0 to match Python `pat.match(ln)`)
        &[
            r"^[\t-\r ]*(?:interface|type|enum|namespace)[\t-\r ]+[A-Za-z0-9_]+",
            r"^:[\t-\r ]*(?:string|number|boolean|any|void)(?-u:\b)",
        ],
        // go
        &[
            r"^[\t-\r ]*(?:func|type|package|import)[\t-\r ]+",
            r"^[\t-\r ]*func[\t-\r ]+\([^)]+\)[\t-\r ]+[A-Za-z0-9_]+",
        ],
        // rust
        &[
            r"^[\t-\r ]*(?:fn|struct|enum|impl|mod|use|pub)[\t-\r ]+",
            r"^[\t-\r ]*#\[",
        ],
    ];
    groups
        .iter()
        .map(|pats| {
            pats.iter()
                .map(|p| Regex::new(p).expect("valid code regex"))
                .collect()
        })
        .collect()
});

struct CharView<'a> {
    raw: &'a str,
    byte_offsets: Vec<usize>,
    chars: Vec<char>,
}

impl<'a> CharView<'a> {
    fn new(raw: &'a str) -> Self {
        let mut byte_offsets = Vec::with_capacity(raw.len() + 1);
        let mut chars = Vec::with_capacity(raw.len());
        for (b, ch) in raw.char_indices() {
            byte_offsets.push(b);
            chars.push(ch);
        }
        byte_offsets.push(raw.len());
        Self {
            raw,
            byte_offsets,
            chars,
        }
    }

    fn len(&self) -> usize {
        self.chars.len()
    }

    fn slice(&self, start_char: usize, end_char: usize) -> &'a str {
        &self.raw[self.byte_offsets[start_char]..self.byte_offsets[end_char]]
    }
}

fn strip_bom(mut text: &str) -> &str {
    while let Some(rest) = text.strip_prefix('\u{feff}') {
        text = rest;
    }
    text
}

fn trim_ascii_ws(text: &str) -> &str {
    text.trim_matches(WS_CHARS)
}

fn is_py_whitespace(c: char) -> bool {
    c.is_whitespace() || matches!(c as u32, 0x1C..=0x1F)
}

fn py_split_words(s: &str) -> usize {
    s.split(is_py_whitespace).filter(|w| !w.is_empty()).count()
}

fn exceeds_json_depth(span: &str, limit: usize) -> bool {
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    for ch in span.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
        } else if ch == '[' || ch == '{' {
            depth += 1;
            if depth > limit {
                return true;
            }
        } else if ch == ']' || ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    false
}

fn loads_strict(span: &str) -> Option<Value> {
    if exceeds_json_depth(span, MAX_JSON_DEPTH) {
        return None;
    }
    serde_json::from_str::<Value>(span).ok()
}

fn matching_open(close: char) -> char {
    if close == '}' { '{' } else { '[' }
}

fn scan_from(
    chars: &[char],
    start: usize,
    known: &mut HashMap<usize, Option<usize>>,
) -> (Option<usize>, usize) {
    let mut stack: Vec<usize> = Vec::new();
    let mut in_str = false;
    let mut esc = false;
    let n = chars.len();
    for (j, &ch) in chars.iter().enumerate().skip(start) {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
        } else if ch == '[' || ch == '{' {
            stack.push(j);
            if stack.len() > MAX_JSON_DEPTH {
                for p in stack {
                    known.insert(p, None);
                }
                return (None, j - start + 1);
            }
        } else if ch == ']' || ch == '}' {
            let Some(&last_open) = stack.last() else {
                return (None, j - start + 1);
            };
            if chars[last_open] != matching_open(ch) {
                for p in stack {
                    known.insert(p, None);
                }
                return (None, j - start + 1);
            }
            let popped = stack.pop().unwrap_or(start);
            known.insert(popped, Some(j + 1));
            if stack.is_empty() {
                return (Some(j + 1), j - start + 1);
            }
        }
    }
    for p in stack {
        known.insert(p, None);
    }
    (None, n - start)
}

/// Port of `scan_json_spans` (`headroom_port/classifier_json_reducer.py`).
pub fn scan_json_spans(text: String) -> Result<Vec<Vec<i64>>, String> {
    let view = CharView::new(&text);
    let n = view.len();
    let budget = SCAN_BUDGET_PER_CHAR
        .saturating_mul(n)
        .saturating_add(SCAN_BUDGET_FLOOR);
    let mut known: HashMap<usize, Option<usize>> = HashMap::new();
    let mut spent = 0usize;
    let mut i = 0usize;

    while i < n {
        let ch = view.chars[i];
        if ch == '[' || ch == '{' {
            let end = if let Some(&cached) = known.get(&i) {
                cached
            } else if spent >= budget {
                return Ok(Vec::new());
            } else {
                let (res, walked) = scan_from(&view.chars, i, &mut known);
                spent = spent.saturating_add(walked);
                res
            };
            if let Some(end_idx) = end {
                i = end_idx;
                continue;
            }
        }
        i += 1;
    }

    let mut candidates: Vec<(usize, usize)> = Vec::new();
    for start in 0..n {
        if let Some(Some(end)) = known.get(&start) {
            candidates.push((start, *end));
        }
    }

    let mut out: Vec<Vec<i64>> = Vec::new();
    let mut covered_until = 0usize;
    let mut parsed_chars = 0usize;

    for (a, b) in candidates {
        if a < covered_until {
            continue;
        }
        let span_len = b - a;
        if parsed_chars.saturating_add(span_len) > budget {
            break;
        }
        parsed_chars += span_len;
        let chunk = view.slice(a, b);
        if let Some(parsed) = loads_strict(chunk)
            && matches!(parsed, Value::Array(_) | Value::Object(_))
        {
            out.push(vec![a as i64, b as i64]);
            covered_until = b;
        }
    }

    Ok(out)
}

fn normalize_concatenated_str(content: &str) -> String {
    let stripped = trim_ascii_ws(strip_bom(content));
    if !stripped.starts_with('{') {
        return String::new();
    }
    let view = CharView::new(stripped);
    let length = view.len();
    let mut idx = 0usize;
    let mut slices: Vec<&str> = Vec::new();
    let mut known: HashMap<usize, Option<usize>> = HashMap::new();

    while idx < length {
        while idx < length && matches!(view.chars[idx], ' ' | '\t' | '\n' | '\r') {
            idx += 1;
        }
        if idx >= length {
            break;
        }
        if view.chars[idx] != '{' {
            return String::new();
        }
        let (Some(end), _) = scan_from(&view.chars, idx, &mut known) else {
            return String::new();
        };
        let raw_obj = view.slice(idx, end);
        let Some(Value::Object(_)) = loads_strict(raw_obj) else {
            return String::new();
        };
        slices.push(raw_obj);
        idx = end;
    }

    if slices.len() >= 2 {
        format!("[{}]", slices.join(","))
    } else {
        String::new()
    }
}

/// Port of `normalize_concatenated_json` (`headroom_port/classifier_json_reducer.py`).
pub fn normalize_concatenated_json(content: String) -> Result<String, String> {
    Ok(normalize_concatenated_str(&content))
}

/// Port of `carries_record_array` (`headroom_port/classifier_json_reducer.py`).
pub fn carries_record_array(span: String) -> Result<bool, String> {
    let cleaned = trim_ascii_ws(strip_bom(&span));
    let Some(root) = loads_strict(cleaned) else {
        return Ok(false);
    };

    let mut stack: Vec<&Value> = vec![&root];
    while let Some(current) = stack.pop() {
        match current {
            Value::Array(arr) => {
                let total = arr.len();
                if total >= 2 {
                    let dicts = arr.iter().filter(|item| item.is_object()).count();
                    if dicts * 5 >= total * 4 {
                        return Ok(true);
                    }
                }
                for item in arr {
                    if item.is_array() || item.is_object() {
                        stack.push(item);
                    }
                }
            }
            Value::Object(map) => {
                for val in map.values() {
                    if val.is_array() || val.is_object() {
                        stack.push(val);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

fn detect_json_kind(content: &str) -> Option<&'static str> {
    let stripped = trim_ascii_ws(strip_bom(content));
    if stripped.is_empty() {
        return None;
    }
    if let Some(val) = loads_strict(stripped) {
        return match val {
            Value::Array(_) => Some("json_array"),
            Value::Object(_) => Some("json_object"),
            _ => None,
        };
    }

    if !normalize_concatenated_str(stripped).is_empty() {
        return Some("json_array");
    }

    let view = CharView::new(stripped);
    let pos_brace = view.chars.iter().position(|&c| c == '{');
    let pos_bracket = view.chars.iter().position(|&c| c == '[');
    let start = match (pos_brace, pos_bracket) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };

    let mut known: HashMap<usize, Option<usize>> = HashMap::new();
    let (Some(end), _) = scan_from(&view.chars, start, &mut known) else {
        return None;
    };
    if (end - start) * 5 < view.len() * 3 {
        return None;
    }
    match loads_strict(view.slice(start, end))? {
        Value::Array(_) => Some("json_array"),
        Value::Object(_) => Some("json_object"),
        _ => None,
    }
}

fn prefix_looks_like_path(prefix: &str) -> bool {
    !prefix.is_empty() && !prefix.contains('<') && !prefix.contains('>') && !prefix.contains('=')
}

fn split_search_line(line: &str) -> Option<(&str, &'static str)> {
    let bytes = line.as_bytes();
    if bytes.is_empty() || bytes[0] == b' ' || bytes[0] == b'\t' {
        return None;
    }
    let start_scan = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
    {
        2
    } else {
        0
    };

    let n = bytes.len();
    let mut i = start_scan;
    while i < n {
        let b = bytes[i];
        if b == b' ' || b == b'\t' {
            return None;
        }
        if (b == b':' || b == b'-') && i > 0 && i + 2 <= n && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < n && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j < n && (bytes[j] == b':' || bytes[j] == b'-') {
                let prefix = &line[..i];
                if !prefix_looks_like_path(prefix) {
                    return None;
                }
                match (b, bytes[j]) {
                    (b':', b':') | (b':', b'-') => return Some((prefix, "match")),
                    (b'-', b'-')
                        if prefix.contains('/')
                            || prefix.contains('\\')
                            || prefix.contains('.') =>
                    {
                        return Some((prefix, "context"));
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }
    None
}

fn is_search_result_line(line: &str) -> bool {
    if TIMESTAMP_ROW_RE.is_match(line) {
        return false;
    }
    split_search_line(line).is_some()
}

fn md_cell_count(row: &str) -> usize {
    trim_ascii_ws(row).trim_matches('|').split('|').count()
}

fn is_md_separator(row: &str) -> bool {
    let cells: Vec<&str> = trim_ascii_ws(row)
        .trim_matches('|')
        .split('|')
        .map(trim_ascii_ws)
        .filter(|c| !c.is_empty())
        .collect();
    if cells.len() < 2 {
        return false;
    }
    cells.into_iter().all(|c| MD_SEP_CELL_RE.is_match(c))
}

fn is_whole_markdown_table(content: &str) -> bool {
    if content.contains("\\|") {
        return false;
    }
    let rows: Vec<&str> = trim_ascii_ws(content).split('\n').collect();
    if rows.len() < 3 || !is_md_separator(rows[1]) {
        return false;
    }
    let cols = md_cell_count(rows[0]);
    if cols < 2 {
        return false;
    }
    let leading_pipe = rows[0].trim_start_matches([' ', '\t']).starts_with('|');
    for &row in &rows[2..] {
        if md_cell_count(row) != cols {
            return false;
        }
        if row.trim_start_matches([' ', '\t']).starts_with('|') != leading_pipe {
            return false;
        }
        if is_md_separator(row) || FIXED_WIDTH_LIST_RE.is_match(row) {
            return false;
        }
    }
    true
}

fn looks_like_prose(sample: &[&str], delim: char) -> bool {
    let enders = sample
        .iter()
        .filter(|r| {
            let trimmed = r.trim_end_matches([' ', '\t', '\r']);
            trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?')
        })
        .count();
    if enders * 2 >= sample.len() {
        return true;
    }
    let mut cell_count = 0usize;
    let mut total_words = 0usize;
    for &r in sample {
        for c in r.split(delim) {
            cell_count += 1;
            total_words += py_split_words(trim_ascii_ws(c));
        }
    }
    total_words > 3 * cell_count
}

fn try_detect_tabular(content: &str) -> bool {
    let lines: Vec<&str> = content
        .split('\n')
        .filter(|ln| !trim_ascii_ws(ln).is_empty())
        .take(50)
        .collect();
    if lines.len() < 3 {
        return false;
    }

    let mut has_md_pair = false;
    for pair in lines.windows(2) {
        if pair[0].contains('|') && is_md_separator(pair[1]) && md_cell_count(pair[0]) >= 2 {
            has_md_pair = true;
            break;
        }
    }

    let delims: &[(char, usize)] = if has_md_pair {
        if is_whole_markdown_table(content) {
            return true;
        }
        &[(',', 85), ('\t', 70), (';', 85)]
    } else {
        &[(',', 85), ('\t', 70), (';', 85), ('|', 85)]
    };

    let sample = &lines[..lines.len().min(20)];
    if sample.len() < 3 {
        return false;
    }

    for &(delim, min_pct) in delims {
        let counts: Vec<usize> = sample
            .iter()
            .map(|row| row.chars().filter(|&c| c == delim).count())
            .collect();
        if counts[0] == 0 {
            continue;
        }
        let mut freq_map: BTreeMap<usize, usize> = BTreeMap::new();
        for &c in &counts {
            *freq_map.entry(c).or_insert(0) += 1;
        }
        let Some((&common_count, &freq)) = freq_map
            .iter()
            .max_by(|(k1, v1), (k2, v2)| v1.cmp(v2).then_with(|| k2.cmp(k1)))
        else {
            continue;
        };
        if common_count == 0 {
            continue;
        }
        let ncols = common_count + 1;
        if ncols < 2 || freq * 100 < sample.len() * min_pct {
            continue;
        }
        if looks_like_prose(sample, delim) {
            continue;
        }
        return true;
    }
    false
}

/// Port of `classify_content` (`headroom_port/classifier_json_reducer.py`).
pub fn classify_content(content: String) -> Result<String, String> {
    let cleaned = strip_bom(&content);
    if cleaned.is_empty() || trim_ascii_ws(cleaned).is_empty() {
        return Ok("text".to_string());
    }

    if let Some(json_kind) = detect_json_kind(cleaned) {
        return Ok(json_kind.to_string());
    }

    if cleaned
        .split('\n')
        .take(500)
        .any(|ln| DIFF_HEADER_RE.is_match(ln))
    {
        return Ok("diff".to_string());
    }

    let sample_html_end = cleaned
        .char_indices()
        .nth(3000)
        .map(|(b, _)| b)
        .unwrap_or(cleaned.len());
    let sample_html = &cleaned[..sample_html_end];
    let has_doctype = HTML_DOCTYPE_RE.is_match(sample_html);
    let has_html = HTML_TAG_RE.is_match(sample_html);
    let has_head = HTML_HEAD_RE.is_match(sample_html);
    let has_body = HTML_BODY_RE.is_match(sample_html);
    let structural = HTML_STRUCTURAL_RE.find_iter(sample_html).count();
    if has_doctype || has_html || structural >= 3 {
        let score = (if has_doctype { 50 } else { 0 })
            + (if has_html { 30 } else { 0 })
            + (if has_head { 10 } else { 0 })
            + (if has_body { 10 } else { 0 })
            + (structural * 3).min(30);
        if score >= 70 {
            return Ok("html".to_string());
        }
    }

    let first_line = cleaned
        .split('\n')
        .next()
        .unwrap_or("")
        .trim_end_matches('\r');
    if first_line.starts_with("On branch ")
        || first_line.starts_with("HEAD detached at ")
        || first_line.starts_with("HEAD detached from ")
    {
        let mut has_heading = false;
        let mut has_path = false;
        let mut section: Option<&str> = None;
        for raw_ln in cleaned.split('\n').skip(1) {
            let ln = raw_ln.trim_end_matches('\r');
            if GIT_STATUS_HEADERS.contains(&ln) {
                has_heading = true;
                section = Some(ln);
            } else if ln.is_empty()
                || ln == "nothing to commit"
                || ln.starts_with("Your branch ")
                || ln.starts_with("  (use ")
            {
                continue;
            } else if section == Some("Untracked files:")
                && let Some(rest) = ln.strip_prefix('\t')
                && !trim_ascii_ws(rest).is_empty()
            {
                has_path = true;
            } else if matches!(
                section,
                Some(
                    "Changes to be committed:"
                        | "Changes not staged for commit:"
                        | "Unmerged paths:"
                )
            ) && GIT_STATUS_ENTRY_RE.is_match(ln)
            {
                has_path = true;
            }
        }
        if has_heading && has_path {
            return Ok("git_status".to_string());
        }
    }

    let search_lines: Vec<&str> = cleaned
        .split('\n')
        .take(100)
        .map(|ln| ln.trim_end_matches('\r'))
        .collect();
    let non_empty_search = search_lines
        .iter()
        .filter(|ln| !trim_ascii_ws(ln).is_empty())
        .count();
    if non_empty_search > 0 {
        let matching_search = search_lines
            .iter()
            .filter(|ln| !trim_ascii_ws(ln).is_empty() && is_search_result_line(ln))
            .count();
        if matching_search >= 2 && matching_search * 3 >= non_empty_search {
            return Ok("search".to_string());
        }
    }

    let log_lines: Vec<&str> = cleaned
        .split('\n')
        .take(200)
        .map(|ln| ln.trim_end_matches('\r'))
        .collect();
    let non_empty_log = log_lines
        .iter()
        .filter(|ln| !trim_ascii_ws(ln).is_empty())
        .count();
    if non_empty_log > 0 {
        let mut pattern_matches = 0usize;
        let mut error_matches = 0usize;
        for &ln in &log_lines {
            for (idx, pat) in LOG_PATTERNS.iter().enumerate() {
                if pat.is_match(ln) {
                    pattern_matches += 1;
                    if idx < 2 {
                        error_matches += 1;
                    }
                    break;
                }
            }
        }
        if pattern_matches > 0
            && pattern_matches * 10 >= non_empty_log
            && (pattern_matches * 50 + error_matches * 5 * non_empty_log) >= 20 * non_empty_log
        {
            return Ok("build".to_string());
        }
    }

    if try_detect_tabular(cleaned) {
        return Ok("tabular".to_string());
    }

    let code_lines: Vec<&str> = cleaned
        .split('\n')
        .take(100)
        .map(|ln| ln.trim_end_matches('\r'))
        .collect();
    let non_empty_code = code_lines
        .iter()
        .filter(|ln| !trim_ascii_ws(ln).is_empty())
        .count()
        .max(1);
    let mut best_score = 0usize;
    for patterns in CODE_PATTERNS.iter() {
        let mut lang_score = 0usize;
        for &ln in &code_lines {
            if patterns.iter().any(|pat| pat.is_match(ln)) {
                lang_score += 1;
            }
        }
        if lang_score > best_score {
            best_score = lang_score;
        }
    }
    if best_score >= 3
        && (40 * non_empty_code + best_score * 40 + best_score * 2 * non_empty_code)
            >= 50 * non_empty_code
    {
        return Ok("source_code".to_string());
    }

    Ok("text".to_string())
}

fn is_float_token(raw_num: &str) -> bool {
    raw_num.contains('.') || raw_num.contains('e') || raw_num.contains('E')
}

fn json_type_tag(val: &Value) -> &'static str {
    match val {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if is_float_token(&n.to_string()) {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "str",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn escape_preview_str(s: &str, max_chars: usize) -> String {
    let sanitized = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    let char_count = sanitized.chars().count();
    if char_count > max_chars {
        let cutoff = max_chars.saturating_sub(3);
        let prefix: String = sanitized.chars().take(cutoff).collect();
        format!("\"{prefix}...\"")
    } else {
        format!("\"{sanitized}\"")
    }
}

fn format_scalar(val: &Value) -> String {
    match val {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Number(n) => {
            let raw = n.to_string();
            if is_float_token(&raw) {
                if raw.parse::<f64>().is_ok_and(|f| f == 0.0) {
                    "0.0".to_string()
                } else {
                    "<float>".to_string()
                }
            } else if raw == "-0" {
                "0".to_string()
            } else {
                raw
            }
        }
        Value::String(s) => escape_preview_str(s, 80),
        _ => json_type_tag(val).to_string(),
    }
}

fn is_error_item(item: &Value) -> bool {
    let Value::Object(map) = item else {
        return false;
    };
    for &k in ERROR_BEARING_KEYS {
        if let Some(v) = map.get(k) {
            let is_empty = match v {
                Value::Null => true,
                Value::Bool(false) => true,
                // Note: in Python `0 == False` (`0 in (None, False, ...)` is True!),
                // so numeric 0 / 0.0 also evaluates as falsy in `(None, False, "", [], {})`.
                Value::Number(n) => {
                    let raw = n.to_string();
                    raw == "0" || raw == "-0" || raw.parse::<f64>().is_ok_and(|f| f == 0.0)
                }
                Value::String(s) => s.is_empty(),
                Value::Array(a) => a.is_empty(),
                Value::Object(o) => o.is_empty(),
                Value::Bool(true) => false,
            };
            if !is_empty {
                return true;
            }
        }
    }
    if let Some(Value::String(status)) = map.get("status") {
        let lower = status.to_lowercase();
        if matches!(lower.as_str(), "error" | "failed" | "failure" | "fatal") {
            return true;
        }
    }
    false
}

fn render_node(val: &Value, depth: usize, max_depth: usize, max_items: usize) -> String {
    let indent = "  ".repeat(depth);
    if depth >= max_depth {
        return match val {
            Value::Array(arr) => format!("{indent}[... len={}]", arr.len()),
            Value::Object(map) => format!("{indent}{{... keys={}}}", map.len()),
            _ => format!("{indent}{}", format_scalar(val)),
        };
    }

    match val {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            format!("{indent}{}", format_scalar(val))
        }
        Value::Array(arr) => {
            let n = arr.len();
            if n == 0 {
                return format!("{indent}[]");
            }
            let head_len = n.min(5);
            let sample_dicts: Vec<&serde_json::Map<String, Value>> = arr[..head_len]
                .iter()
                .filter_map(Value::as_object)
                .collect();
            let schema_header = if sample_dicts.len() >= 2 && sample_dicts.len() == head_len {
                let mut field_types: BTreeMap<&str, BTreeSet<&'static str>> = BTreeMap::new();
                for d in &sample_dicts {
                    for (k, v) in *d {
                        field_types
                            .entry(k.as_str())
                            .or_default()
                            .insert(json_type_tag(v));
                    }
                }
                let cols: Vec<String> = field_types
                    .into_iter()
                    .map(|(k, types)| {
                        let joined: Vec<&str> = types.into_iter().collect();
                        format!("{k}:{}", joined.join("|"))
                    })
                    .collect();
                let cols_str = if cols.len() > 12 {
                    format!("{}, ... +{} fields", cols[..12].join(", "), cols.len() - 12)
                } else {
                    cols.join(", ")
                };
                format!(" schema={{{cols_str}}}")
            } else {
                String::new()
            };

            let first_take = n.min(max_items);
            let mut selected_indices: Vec<usize> = (0..first_take).collect();
            for (offset, item) in arr.iter().skip(first_take).enumerate() {
                if selected_indices.len() >= max_items + 3 {
                    break;
                }
                if is_error_item(item) {
                    selected_indices.push(first_take + offset);
                }
            }

            let mut lines = vec![format!("{indent}Array(len={n}){schema_header} [")];
            for idx in &selected_indices {
                let rendered = render_node(&arr[*idx], depth + 1, max_depth, max_items);
                lines.push(format!("{rendered},"));
            }
            let omitted = n - selected_indices.len();
            if omitted > 0 {
                lines.push(format!("{indent}  ... +{omitted} more items"));
            }
            lines.push(format!("{indent}]"));
            lines.join("\n")
        }
        Value::Object(map) => {
            if map.is_empty() {
                return format!("{indent}{{}}");
            }
            let mut all_keys: Vec<&String> = map.keys().collect();
            all_keys.sort();
            let mut priority: Vec<&String> = Vec::new();
            let mut regular: Vec<&String> = Vec::new();
            for k in &all_keys {
                if PRIORITY_KEYS.contains(&k.as_str()) {
                    priority.push(*k);
                } else {
                    regular.push(*k);
                }
            }
            let key_cap = 12usize.max(max_items * 4);
            let reg_take = key_cap.saturating_sub(priority.len());
            let mut chosen = priority;
            chosen.extend(regular.into_iter().take(reg_take));

            let mut lines = vec![format!("{indent}Object(keys={}) {{", map.len())];
            for k in &chosen {
                let v = &map[*k];
                let key_label = escape_preview_str(k, 60);
                if !v.is_array() && !v.is_object() {
                    lines.push(format!("{indent}  {key_label}: {}", format_scalar(v)));
                } else {
                    lines.push(format!("{indent}  {key_label}:"));
                    lines.push(render_node(v, depth + 2, max_depth, max_items));
                }
            }
            let omitted_keys = all_keys.len() - chosen.len();
            if omitted_keys > 0 {
                lines.push(format!("{indent}  ... +{omitted_keys} more keys"));
            }
            lines.push(format!("{indent}}}"));
            lines.join("\n")
        }
    }
}

/// Port of `reduce_json_structure` (`headroom_port/classifier_json_reducer.py`).
pub fn reduce_json_structure(
    content: String,
    max_depth: Option<i64>,
    max_items: Option<i64>,
) -> Result<String, String> {
    if content.contains("<<ccr:") || content.contains("context-engine:") {
        return Ok(String::new());
    }
    let stripped = trim_ascii_ws(strip_bom(&content));
    if stripped.is_empty() {
        return Ok(String::new());
    }
    let eff_depth = max_depth.unwrap_or(4).clamp(1, 16) as usize;
    let eff_items = max_items.unwrap_or(3).clamp(1, 20) as usize;

    let normalized = normalize_concatenated_str(stripped);
    let target = if normalized.is_empty() {
        stripped
    } else {
        normalized.as_str()
    };

    let Some(parsed) = loads_strict(target) else {
        return Ok(String::new());
    };
    if !parsed.is_array() && !parsed.is_object() {
        return Ok(String::new());
    }

    Ok(render_node(&parsed, 0, eff_depth, eff_items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_formats() {
        assert_eq!(
            classify_content(r#"[{"id":1},{"id":2}]"#.to_string()).unwrap(),
            "json_array"
        );
        assert_eq!(
            classify_content("\u{feff}{\"ok\":true}".to_string()).unwrap(),
            "json_object"
        );
        assert_eq!(
            classify_content(r#"{"a":1} {"b":2}"#.to_string()).unwrap(),
            "json_array"
        );
        assert_eq!(
            classify_content(
                "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,1 @@\n-old\n+new"
                    .to_string()
            )
            .unwrap(),
            "diff"
        );
        assert_eq!(
            classify_content(
                "On branch main\nChanges not staged for commit:\n\tmodified:   Cargo.toml"
                    .to_string()
            )
            .unwrap(),
            "git_status"
        );
        assert_eq!(
            classify_content(
                "C:\\repo\\src\\main.rs:42:fn main() {}\nC:\\repo\\src\\main.rs-43-}".to_string()
            )
            .unwrap(),
            "search"
        );
        assert_eq!(
            classify_content(
                "2026-11-22 12:00:00 [ERROR] failed\n2026-11-22 12:00:01 [INFO] retry".to_string()
            )
            .unwrap(),
            "build"
        );
    }

    #[test]
    fn test_unicode_char_spans_and_reduction() {
        let spans = scan_json_spans("🦀 {\"k\": \"🚀\"} end".to_string()).unwrap();
        assert_eq!(spans, vec![vec![2, 12]]);
        assert!(carries_record_array(r#"[{"a":1},{"a":2}]"#.to_string()).unwrap());
        assert!(!carries_record_array("[1,2,3]".to_string()).unwrap());
        let reduced = reduce_json_structure(
            r#"[{"id":1,"status":"ok"},{"id":2,"status":"ok"},{"id":3,"status":"failed","error":"boom"}]"#
                .to_string(),
            Some(4),
            Some(1),
        )
        .unwrap();
        assert!(reduced.contains("Array(len=3) schema={error:str, id:int, status:str}"));
        assert!(reduced.contains("\"boom\""));
    }
}
