//! Deterministic pre-storage and pre-index secret scanner/redactor (`SecretGuard`, ADR 0002).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

use crate::error::{ContextError, Result};

/// Enforcement mode when [`SecretGuard`] detects one or more secrets in a stream or document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecretPolicyMode {
    /// Redacts every detected secret (`[REDACTED:<RULE_ID>]`) before compact view generation,
    /// FTS5 indexing, or journal logging. When secrets are present, raw unredacted bytes are
    /// withheld unless `allow_raw_blob_when_redacted` is explicitly enabled in local policy.
    #[default]
    RedactBeforeIndex,
    /// Redacts compact views and FTS5 chunks while quarantining the artifact so `context_get`
    /// refuses raw recovery (`originals_available = false`).
    Quarantine,
    /// Fails closed (`ContextError::SecretPolicyDenied`) before writing any blob, index row,
    /// or view when a secret is detected.
    Deny,
}

/// Workspace secret-protection configuration consumed by [`SecretGuard`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPolicy {
    pub mode: SecretPolicyMode,
    /// Enables high-entropy unprefixed token scanning in addition to explicit regex rules.
    pub enable_entropy_detection: bool,
    /// Minimum token length considered by the high-entropy detector (`28` chars default).
    pub entropy_min_length: usize,
    /// Minimum Shannon entropy in hundredths of bits per char (`415` = `4.15` bits/char default).
    pub entropy_threshold_bits_x100: u32,
    /// Whether raw unredacted blobs may be persisted under `RedactBeforeIndex` when secrets
    /// are detected. Defaults to `false` (sanitized-only persistence).
    pub allow_raw_blob_when_redacted: bool,
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self {
            mode: SecretPolicyMode::RedactBeforeIndex,
            enable_entropy_detection: true,
            entropy_min_length: 28,
            entropy_threshold_bits_x100: 415,
            allow_raw_blob_when_redacted: false,
        }
    }
}

/// Categorizes detected secret credentials without exposing the matched secret value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRuleKind {
    PemPrivateKey,
    AwsAccessKey,
    AwsSecretKey,
    GcpApiKey,
    GcpOAuthToken,
    GitHubToken,
    GitLabToken,
    OpenAiApiKey,
    AnthropicApiKey,
    SlackToken,
    SlackWebhook,
    JwtToken,
    AuthHeader,
    ConnectionUri,
    EnvSecretAssignment,
    HighEntropyToken,
}

impl SecretRuleKind {
    /// Stable uppercase rule identifier used in `[REDACTED:<RULE_ID>]` placeholders.
    #[must_use]
    pub const fn rule_id(&self) -> &'static str {
        match self {
            Self::PemPrivateKey => "PEM_PRIVATE_KEY",
            Self::AwsAccessKey => "AWS_ACCESS_KEY",
            Self::AwsSecretKey => "AWS_SECRET_KEY",
            Self::GcpApiKey => "GCP_API_KEY",
            Self::GcpOAuthToken => "GCP_OAUTH_TOKEN",
            Self::GitHubToken => "GITHUB_TOKEN",
            Self::GitLabToken => "GITLAB_TOKEN",
            Self::OpenAiApiKey => "OPENAI_API_KEY",
            Self::AnthropicApiKey => "ANTHROPIC_API_KEY",
            Self::SlackToken => "SLACK_TOKEN",
            Self::SlackWebhook => "SLACK_WEBHOOK",
            Self::JwtToken => "JWT_TOKEN",
            Self::AuthHeader => "AUTH_HEADER",
            Self::ConnectionUri => "CONNECTION_URI",
            Self::EnvSecretAssignment => "ENV_SECRET",
            Self::HighEntropyToken => "HIGH_ENTROPY_TOKEN",
        }
    }

    /// Deterministic replacement marker (`[REDACTED:<RULE_ID>]`).
    #[must_use]
    pub fn placeholder(&self) -> String {
        format!("[REDACTED:{}]", self.rule_id())
    }
}

/// Non-sensitive metadata about a single redacted secret span (`byte_start..byte_end` in input).
///
/// Intentionally omits the raw secret substring so findings are safe to log or serialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    pub kind: SecretRuleKind,
    pub rule_id: &'static str,
    pub byte_start: usize,
    pub byte_end: usize,
}

/// Result of scanning and redacting a UTF-8 string via [`SecretGuard::scan_str`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretScanReport {
    pub sanitized_text: String,
    pub findings: Vec<SecretFinding>,
}

impl SecretScanReport {
    #[must_use]
    pub fn has_secrets(&self) -> bool {
        !self.findings.is_empty()
    }

    #[must_use]
    pub fn redacted_count(&self) -> usize {
        self.findings.len()
    }

    /// Deduplicated, deterministically sorted list of triggered rule IDs.
    #[must_use]
    pub fn distinct_rule_ids(&self) -> Vec<String> {
        let set: BTreeSet<&'static str> = self.findings.iter().map(|f| f.rule_id).collect();
        set.into_iter().map(str::to_string).collect()
    }
}

/// Policy-enforced disposition produced by [`SecretGuard::protect_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamProtectionOutcome {
    /// Bytes safe to persist when raw storage is disallowed, or identical to `raw` when clean.
    pub persistence_bytes: Vec<u8>,
    /// Sanitized UTF-8 text safe for compact reducers and SQLite FTS5 indexing (`None` for pure binary).
    pub sanitized_index_text: Option<String>,
    /// Recorded secret findings (empty when stream is clean).
    pub findings: Vec<SecretFinding>,
    /// `true` if `persistence_bytes` equals the untouched original raw byte stream.
    pub exact_raw_preserved: bool,
    /// `true` if `context_get` is permitted to serve content from this stream to an agent.
    pub originals_available: bool,
    /// `true` if the stream was quarantined under [`SecretPolicyMode::Quarantine`].
    pub quarantined: bool,
}

impl StreamProtectionOutcome {
    #[must_use]
    pub fn distinct_rule_ids(&self) -> Vec<String> {
        let set: BTreeSet<&'static str> = self.findings.iter().map(|f| f.rule_id).collect();
        set.into_iter().map(str::to_string).collect()
    }
}

struct CompiledRule {
    kind: SecretRuleKind,
    priority: u8,
    capture_group: usize,
    regex: Regex,
}

struct CompiledScanner {
    fast_set: RegexSet,
    rules: Vec<CompiledRule>,
    env_assignment_re: Regex,
    entropy_candidate_re: Regex,
}

static COMPILED_SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let raw_rules: Vec<(SecretRuleKind, u8, usize, &str)> = vec![
        // Priority 1: Multi-line and truncated PEM private key blocks
        (
            SecretRuleKind::PemPrivateKey,
            1,
            0,
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        ),
        (
            SecretRuleKind::PemPrivateKey,
            1,
            0,
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*",
        ),
        // Priority 2: Credentialed connection URIs, Authorization headers, Slack webhooks
        (
            SecretRuleKind::ConnectionUri,
            2,
            1,
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver|clickhouse)://([^/\s@]*:[^/\s@]+)@",
        ),
        (
            SecretRuleKind::AuthHeader,
            2,
            1,
            r#"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic|Digest|Token|ApiKey)\s+([^\s"';,\r\n]+)"#,
        ),
        (
            SecretRuleKind::AuthHeader,
            2,
            1,
            r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)",
        ),
        (
            SecretRuleKind::SlackWebhook,
            2,
            0,
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        ),
        // Priority 3: Vendor-prefixed API keys, cloud keys, and JWTs
        (
            SecretRuleKind::AnthropicApiKey,
            3,
            0,
            r"\bsk-ant-[A-Za-z0-9\-_]{16,}\b",
        ),
        (
            SecretRuleKind::OpenAiApiKey,
            3,
            0,
            r"\bsk-(?:proj-|svcacct-|live-|test-)?[A-Za-z0-9\-_]{20,}\b",
        ),
        (
            SecretRuleKind::GitHubToken,
            3,
            0,
            r"\b(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{22,})\b",
        ),
        (
            SecretRuleKind::GitLabToken,
            3,
            0,
            r"\b(?:glpat|glptt|gldt|glrt|gloas)-[A-Za-z0-9\-_]{20,}\b",
        ),
        (
            SecretRuleKind::AwsAccessKey,
            3,
            0,
            r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        ),
        (
            SecretRuleKind::AwsSecretKey,
            3,
            1,
            r#"(?i)\baws_secret_access_key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        ),
        (
            SecretRuleKind::GcpApiKey,
            3,
            0,
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
        ),
        (
            SecretRuleKind::GcpOAuthToken,
            3,
            0,
            r"\bya29\.[0-9A-Za-z\-_]{20,}\b",
        ),
        (
            SecretRuleKind::SlackToken,
            3,
            0,
            r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
        ),
        (
            SecretRuleKind::JwtToken,
            3,
            0,
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        ),
    ];

    let patterns: Vec<&str> = raw_rules.iter().map(|(_, _, _, pat)| *pat).collect();
    let fast_set = RegexSet::new(&patterns).expect("valid static SecretGuard RegexSet");
    let rules = raw_rules
        .into_iter()
        .map(|(kind, priority, capture_group, pat)| CompiledRule {
            kind,
            priority,
            capture_group,
            regex: Regex::new(pat).expect("valid static SecretGuard Regex"),
        })
        .collect();

    let env_assignment_re = Regex::new(
        r#"(?im)(?:^|[\s,{(&?])(?:export\s+)?["']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY|CLIENT_SECRET|WEBHOOK_SECRET|SIGNING_KEY|ENCRYPTION_KEY)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*(?P<val>"[^"\r\n]{4,}"|'[^'\r\n]{4,}'|[^\s"',}#;&\r\n]{4,})"#,
    )
    .expect("valid env_assignment_re");

    let entropy_candidate_re =
        Regex::new(r"[A-Za-z0-9+/=_-]{24,}").expect("valid entropy_candidate_re");

    CompiledScanner {
        fast_set,
        rules,
        env_assignment_re,
        entropy_candidate_re,
    }
});

#[derive(Debug, Clone, Copy)]
struct CandidateSpan {
    start: usize,
    end: usize,
    priority: u8,
    kind: SecretRuleKind,
}

/// Deterministic pre-persistence and pre-index secret scanner/redactor.
#[derive(Debug, Clone, Default)]
pub struct SecretGuard {
    policy: SecretPolicy,
}

impl SecretGuard {
    /// Constructs a [`SecretGuard`] configured with `policy`.
    #[must_use]
    pub const fn new(policy: SecretPolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub const fn policy(&self) -> &SecretPolicy {
        &self.policy
    }

    /// Scans `input` and returns a [`SecretScanReport`] with redacted text and non-sensitive findings.
    #[must_use]
    pub fn scan_str(&self, input: &str) -> SecretScanReport {
        if input.is_empty() {
            return SecretScanReport {
                sanitized_text: String::new(),
                findings: Vec::new(),
            };
        }

        let scanner = &*COMPILED_SCANNER;
        let mut candidates: Vec<CandidateSpan> = Vec::new();

        // 1. Fast-path RegexSet over explicit vendor/header/URI/PEM patterns.
        for rule_idx in scanner.fast_set.matches(input).into_iter() {
            let rule = &scanner.rules[rule_idx];
            if rule.capture_group == 0 {
                for mat in rule.regex.find_iter(input) {
                    if !is_already_redacted_slice(&input[mat.start()..mat.end()]) {
                        candidates.push(CandidateSpan {
                            start: mat.start(),
                            end: mat.end(),
                            priority: rule.priority,
                            kind: rule.kind,
                        });
                    }
                }
            } else {
                for caps in rule.regex.captures_iter(input) {
                    if let Some(group) = caps.get(rule.capture_group) {
                        if !is_already_redacted_slice(group.as_str()) {
                            candidates.push(CandidateSpan {
                                start: group.start(),
                                end: group.end(),
                                priority: rule.priority,
                                kind: rule.kind,
                            });
                        }
                    }
                }
            }
        }

        // 2. Sensitive `.env`, CLI, JSON, and YAML key=value assignments (Priority 4).
        for caps in scanner.env_assignment_re.captures_iter(input) {
            let Some(key_match) = caps.name("key") else {
                continue;
            };
            let Some(val_match) = caps.name("val") else {
                continue;
            };

            if is_non_secret_telemetry_key(key_match.as_str()) {
                continue;
            }

            let (val_start, val_end) =
                trim_surrounding_quotes(input, val_match.start(), val_match.end());
            if val_end <= val_start {
                continue;
            }
            let inner_val = &input[val_start..val_end];
            if is_benign_assignment_value(inner_val) {
                continue;
            }

            candidates.push(CandidateSpan {
                start: val_start,
                end: val_end,
                priority: 4,
                kind: SecretRuleKind::EnvSecretAssignment,
            });
        }

        // 3. High-entropy unprefixed secret token detection (Priority 5).
        if self.policy.enable_entropy_detection {
            let min_len = self.policy.entropy_min_length.max(16);
            let threshold = f64::from(self.policy.entropy_threshold_bits_x100) / 100.0;

            for mat in scanner.entropy_candidate_re.find_iter(input) {
                let token = mat.as_str();
                if token.len() < min_len {
                    continue;
                }
                if is_exempt_from_entropy_rule(input, mat.start(), mat.end(), token) {
                    continue;
                }
                if shannon_entropy_bits(token) >= threshold {
                    candidates.push(CandidateSpan {
                        start: mat.start(),
                        end: mat.end(),
                        priority: 5,
                        kind: SecretRuleKind::HighEntropyToken,
                    });
                }
            }
        }

        if candidates.is_empty() {
            return SecretScanReport {
                sanitized_text: input.to_string(),
                findings: Vec::new(),
            };
        }

        // Deterministic conflict resolution: higher specificity (lower priority number) wins first,
        // then earlier byte offset, then longer span.
        candidates.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.start.cmp(&b.start))
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
        });

        let mut accepted: Vec<CandidateSpan> = Vec::with_capacity(candidates.len());
        for cand in candidates {
            if cand.start >= cand.end
                || !input.is_char_boundary(cand.start)
                || !input.is_char_boundary(cand.end)
            {
                continue;
            }
            let overlaps = accepted
                .iter()
                .any(|existing| cand.start < existing.end && existing.start < cand.end);
            if !overlaps {
                accepted.push(cand);
            }
        }

        accepted.sort_by_key(|span| span.start);

        let mut sanitized = String::with_capacity(input.len());
        let mut findings = Vec::with_capacity(accepted.len());
        let mut cursor = 0usize;

        for span in accepted {
            sanitized.push_str(&input[cursor..span.start]);
            sanitized.push_str(&span.kind.placeholder());
            findings.push(SecretFinding {
                kind: span.kind,
                rule_id: span.kind.rule_id(),
                byte_start: span.start,
                byte_end: span.end,
            });
            cursor = span.end;
        }
        sanitized.push_str(&input[cursor..]);

        SecretScanReport {
            sanitized_text: sanitized,
            findings,
        }
    }

    /// Convenience helper returning the redacted UTF-8 string directly.
    #[must_use]
    pub fn redact_str(&self, input: &str) -> String {
        self.scan_str(input).sanitized_text
    }

    /// Applies [`SecretGuard`] and [`SecretPolicy`] to an arbitrary raw byte stream (UTF-8 or binary).
    ///
    /// - Clean UTF-8 streams preserve exact raw bytes and expose sanitized text for FTS5/views.
    /// - Clean binary streams preserve exact raw bytes and set `sanitized_index_text = None`.
    /// - Streams containing secrets follow `RedactBeforeIndex`, `Quarantine`, or `Deny` fail-closed rules.
    pub fn protect_bytes(&self, raw: &[u8]) -> Result<StreamProtectionOutcome> {
        let is_binary = raw.contains(&0) || std::str::from_utf8(raw).is_err();
        let lossy = String::from_utf8_lossy(raw);
        let report = self.scan_str(&lossy);

        if !report.has_secrets() {
            return Ok(StreamProtectionOutcome {
                persistence_bytes: raw.to_vec(),
                sanitized_index_text: if is_binary {
                    None
                } else {
                    Some(report.sanitized_text)
                },
                findings: Vec::new(),
                exact_raw_preserved: true,
                originals_available: true,
                quarantined: false,
            });
        }

        match self.policy.mode {
            SecretPolicyMode::Deny => Err(ContextError::SecretPolicyDenied {
                findings_count: report.redacted_count(),
                rule_ids: report.distinct_rule_ids(),
            }),
            SecretPolicyMode::Quarantine => Ok(StreamProtectionOutcome {
                persistence_bytes: Vec::new(),
                sanitized_index_text: if is_binary {
                    None
                } else {
                    Some(report.sanitized_text)
                },
                findings: report.findings,
                exact_raw_preserved: false,
                originals_available: false,
                quarantined: true,
            }),
            SecretPolicyMode::RedactBeforeIndex => {
                if self.policy.allow_raw_blob_when_redacted {
                    Ok(StreamProtectionOutcome {
                        persistence_bytes: raw.to_vec(),
                        sanitized_index_text: if is_binary {
                            None
                        } else {
                            Some(report.sanitized_text)
                        },
                        findings: report.findings,
                        exact_raw_preserved: true,
                        originals_available: true,
                        quarantined: false,
                    })
                } else {
                    let sanitized_bytes = report.sanitized_text.as_bytes().to_vec();
                    Ok(StreamProtectionOutcome {
                        persistence_bytes: sanitized_bytes,
                        sanitized_index_text: if is_binary {
                            None
                        } else {
                            Some(report.sanitized_text)
                        },
                        findings: report.findings,
                        exact_raw_preserved: false,
                        originals_available: !is_binary,
                        quarantined: false,
                    })
                }
            }
        }
    }
}

/// Computes deterministic Shannon entropy in bits per byte over `token`.
#[must_use]
pub fn shannon_entropy_bits(token: &str) -> f64 {
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn trim_surrounding_quotes(input: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = input.as_bytes();
    if end >= start + 2 {
        let first = bytes[start];
        let last = bytes[end - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return (start + 1, end - 1);
        }
    }
    (start, end)
}

fn is_already_redacted_slice(s: &str) -> bool {
    s.contains("[REDACTED:")
}

fn is_non_secret_telemetry_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.ends_with("tokens")
        || lower.contains("token_count")
        || lower.contains("token_limit")
        || lower.contains("token_budget")
        || lower.contains("token_estimate")
        || lower.contains("max_token")
        || lower == "secrets_redacted"
        || lower == "secret_rule_ids"
}

fn is_benign_assignment_value(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.len() < 4 || is_already_redacted_slice(trimmed) {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "none" | "nil" | "undefined" | "empty" | "redacted" | "todo"
    ) {
        return true;
    }
    // Variable interpolation placeholders such as `${API_KEY}` or `<YOUR_TOKEN>`
    if (trimmed.starts_with("${") && trimmed.ends_with('}'))
        || (trimmed.starts_with('<') && trimmed.ends_with('>'))
    {
        return true;
    }
    false
}

fn is_exempt_from_entropy_rule(full_input: &str, start: usize, end: usize, token: &str) -> bool {
    if is_already_redacted_slice(token) {
        return true;
    }

    // Exempt Context Engine ArtifactIds (`a_<64-hex>`) and WorkspaceScopeIds (`ws_<32-hex>`).
    if let Some(hex_part) = token.strip_prefix("a_") {
        if hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
    }
    if let Some(hex_part) = token.strip_prefix("ws_") {
        if hex_part.len() == 32 && hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
    }

    // Exempt pure hexadecimal digests (Git commit SHAs, SHA-256, MD5, SHA-512) and standard UUIDs.
    if token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if is_uuid_like(token) {
        return true;
    }

    // Exempt tokens immediately attached to file-path separators (`/`, `\`, `::`, `.rs`, etc.)
    // unless preceded by `=` or `:` or quotes (secret assignment context).
    let prev_byte = start
        .checked_sub(1)
        .and_then(|idx| full_input.as_bytes().get(idx).copied());
    let next_byte = full_input.as_bytes().get(end).copied();
    if matches!(prev_byte, Some(b'/' | b'\\' | b'.'))
        || matches!(next_byte, Some(b'/' | b'\\' | b'.'))
    {
        return true;
    }

    // Require mixed character classes typical of generated credentials:
    // at least 3 character classes among {upper, lower, digit, symbol} and >= 2 digits,
    // and avoid snake_case Rust/Python function names (`_` count > 2).
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut digits = 0usize;
    let mut symbols = 0usize;
    let mut underscores = 0usize;

    for b in token.bytes() {
        if b.is_ascii_uppercase() {
            upper += 1;
        } else if b.is_ascii_lowercase() {
            lower += 1;
        } else if b.is_ascii_digit() {
            digits += 1;
        } else {
            symbols += 1;
            if b == b'_' {
                underscores += 1;
            }
        }
    }

    if underscores > 2 || digits < 2 {
        return true;
    }

    let classes = usize::from(upper > 0)
        + usize::from(lower > 0)
        + usize::from(digits > 0)
        + usize::from(symbols > 0);
    classes < 3
}

fn is_uuid_like(token: &str) -> bool {
    let parts: Vec<&str> = token.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected = [8usize, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected.iter())
        .all(|(part, &len)| part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit()))
}
