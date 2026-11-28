//! Server-bound workspace scopes, validated session identifiers, and opaque `a_<sha256>` artifact IDs.

use std::fmt;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ContextError, Result};

/// SHA-256 hex digest of an empty byte slice (`b""`).
pub const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Default session identifier when none is explicitly provided.
pub const DEFAULT_SESSION_ID: &str = "default";

/// Computes a lowercase 64-character hexadecimal SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Returns the current UTC timestamp formatted in RFC 3339 (`YYYY-MM-DDTHH:MM:SS.sssZ`).
#[must_use]
pub fn now_rfc3339_utc() -> String {
    format!("{:.3}", Timestamp::now())
}

/// Server-derived canonical workspace scope identifier (`ws_<32-hex>`).
///
/// Never accepted as a raw path or unverified client override for authorization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceScopeId(String);

impl WorkspaceScopeId {
    /// Prefix carried by all valid [`WorkspaceScopeId`] values.
    pub const PREFIX: &'static str = "ws_";
    /// Number of lowercase hex characters following [`Self::PREFIX`].
    pub const HEX_LEN: usize = 32;

    /// Resolves `workspace_root` via `dunce::canonicalize`, validates that it is an existing
    /// directory, and computes its deterministic [`WorkspaceScopeId`].
    pub fn from_workspace_root(workspace_root: impl AsRef<Path>) -> Result<(Self, PathBuf)> {
        let raw_path = workspace_root.as_ref();
        let canonical =
            dunce::canonicalize(raw_path).map_err(|err| ContextError::InvalidWorkspacePath {
                path: raw_path.display().to_string(),
                reason: err.to_string(),
            })?;

        if !canonical.is_dir() {
            return Err(ContextError::InvalidWorkspacePath {
                path: canonical.display().to_string(),
                reason: "workspace root must be an existing directory".to_string(),
            });
        }

        let canonical_str = canonical.to_string_lossy();
        let id = Self::from_canonical_path_str(&canonical_str);
        Ok((id, canonical))
    }

    /// Computes a deterministic [`WorkspaceScopeId`] from an already-canonicalized path string.
    ///
    /// Normalizes Windows drive letters (`d:\...` -> `D:\...`) and strips redundant trailing
    /// path separators (except root `/` or `C:\`) so scope hashes remain stable.
    #[must_use]
    pub fn from_canonical_path_str(canonical_path: &str) -> Self {
        let normalized = normalize_canonical_path_for_hash(canonical_path);
        let mut hasher = Sha256::new();
        hasher.update(b"context-engine:workspace-scope:v1\0");
        hasher.update(normalized.as_bytes());
        let digest = hex::encode(hasher.finalize());
        Self(format!("{}{}", Self::PREFIX, &digest[..Self::HEX_LEN]))
    }

    /// Parses and validates a serialized `ws_<32-lowercase-hex>` scope identifier.
    pub fn parse(raw: &str) -> Result<Self> {
        let Some(hex_part) = raw.strip_prefix(Self::PREFIX) else {
            return Err(ContextError::ScopeViolation {
                expected_workspace: "ws_<32-hex>".to_string(),
                actual_workspace: raw.to_string(),
                detail: "missing 'ws_' prefix".to_string(),
            });
        };

        if hex_part.len() != Self::HEX_LEN || !is_lowercase_hex(hex_part) {
            return Err(ContextError::ScopeViolation {
                expected_workspace: "ws_<32-lowercase-hex>".to_string(),
                actual_workspace: raw.to_string(),
                detail: "scope id must contain 32 lowercase hexadecimal characters".to_string(),
            });
        }

        Ok(Self(raw.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkspaceScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for WorkspaceScopeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validated session identifier (`[A-Za-z0-9._-]{1,128}`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Maximum byte length of a [`SessionId`].
    pub const MAX_LEN: usize = 128;

    /// Validates and constructs a [`SessionId`].
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();
        Self::validate_str(&s)?;
        Ok(Self(s))
    }

    /// Parses a [`SessionId`] from `&str`.
    pub fn parse(raw: &str) -> Result<Self> {
        Self::validate_str(raw)?;
        Ok(Self(raw.to_string()))
    }

    /// Returns the default session identifier (`"default"`).
    #[must_use]
    pub fn default_session() -> Self {
        Self(DEFAULT_SESSION_ID.to_string())
    }

    fn validate_str(raw: &str) -> Result<()> {
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return Err(ContextError::InvalidSessionId {
                session_id: raw.to_string(),
                reason: format!("length must be between 1 and {} characters", Self::MAX_LEN),
            });
        }
        if raw == "." || raw == ".." || raw.starts_with('-') {
            return Err(ContextError::InvalidSessionId {
                session_id: raw.to_string(),
                reason: "session id cannot be '.', '..', or start with '-'".to_string(),
            });
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ContextError::InvalidSessionId {
                session_id: raw.to_string(),
                reason: "only ASCII alphanumeric, '.', '_', and '-' characters are permitted"
                    .to_string(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::default_session()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Authoritative server-bound `(workspace_root, workspace_scope_id, session_id)` context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundScope {
    pub workspace_root: PathBuf,
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
}

impl BoundScope {
    /// Binds to `workspace_root` (canonicalizing it via `dunce`) and validates `session_id`
    /// (defaulting to `"default"` if `None`).
    pub fn bind(workspace_root: impl AsRef<Path>, session_id: Option<&str>) -> Result<Self> {
        let (workspace_scope_id, canonical_root) =
            WorkspaceScopeId::from_workspace_root(workspace_root)?;
        let session = match session_id {
            Some(s) => SessionId::parse(s)?,
            None => SessionId::default_session(),
        };
        Ok(Self {
            workspace_root: canonical_root,
            workspace_scope_id,
            session_id: session,
        })
    }

    /// Returns a cloned [`BoundScope`] targeting a different validated session within the
    /// **same** canonical workspace.
    pub fn with_session(&self, session_id: &str) -> Result<Self> {
        Ok(Self {
            workspace_root: self.workspace_root.clone(),
            workspace_scope_id: self.workspace_scope_id.clone(),
            session_id: SessionId::parse(session_id)?,
        })
    }

    /// Verifies optional client-supplied scope parameters against the server-bound workspace.
    ///
    /// - Any mismatch on `client_project_scope` fails closed with [`ContextError::ScopeViolation`].
    /// - If `client_session_id` is supplied, validates its syntax and returns the narrowed scope.
    pub fn resolve_request_scope(
        &self,
        client_project_scope: Option<&str>,
        client_session_id: Option<&str>,
    ) -> Result<Self> {
        if let Some(supplied_ws) = client_project_scope {
            if supplied_ws != self.workspace_scope_id.as_str() {
                return Err(ContextError::ScopeViolation {
                    expected_workspace: self.workspace_scope_id.as_str().to_string(),
                    actual_workspace: supplied_ws.to_string(),
                    detail: "client-supplied project_scope cannot override server-bound workspace"
                        .to_string(),
                });
            }
        }

        match client_session_id {
            Some(sess) => self.with_session(sess),
            None => Ok(self.clone()),
        }
    }

    /// Verifies that an artifact record's `(stored_workspace, stored_session)` matches this scope.
    pub fn verify_exact_scope(
        &self,
        stored_workspace: &WorkspaceScopeId,
        stored_session: &SessionId,
    ) -> Result<()> {
        if stored_workspace != &self.workspace_scope_id {
            return Err(ContextError::ScopeViolation {
                expected_workspace: self.workspace_scope_id.as_str().to_string(),
                actual_workspace: stored_workspace.as_str().to_string(),
                detail: "cross-workspace artifact access denied".to_string(),
            });
        }
        if stored_session != &self.session_id {
            return Err(ContextError::SessionMismatch {
                expected_session: self.session_id.as_str().to_string(),
                actual_session: stored_session.as_str().to_string(),
            });
        }
        Ok(())
    }

    /// Root `.context-engine` state directory inside the bound workspace.
    #[must_use]
    pub fn engine_dir(&self) -> PathBuf {
        self.workspace_root.join(".context-engine")
    }

    /// Content-addressed blob store directory (`.context-engine/store`).
    #[must_use]
    pub fn store_dir(&self) -> PathBuf {
        self.engine_dir().join("store")
    }

    /// Per-workspace SQLite WAL database path (`.context-engine/index.db`).
    #[must_use]
    pub fn index_db_path(&self) -> PathBuf {
        self.engine_dir().join("index.db")
    }
}

/// Opaque server-minted artifact identifier (`a_<64-lowercase-hex>`).
///
/// Computed from domain-separated SHA-256 inputs bound to `(WorkspaceScopeId, SessionId)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Prefix carried by all valid [`ArtifactId`] values.
    pub const PREFIX: &'static str = "a_";
    /// Number of lowercase hex characters following [`Self::PREFIX`].
    pub const HEX_LEN: usize = 64;

    /// Mints a deterministic, domain-separated [`ArtifactId`] bound to `scope`.
    #[must_use]
    pub fn mint(
        scope: &BoundScope,
        captured_at_rfc3339: &str,
        sequence_or_nonce: u64,
        stdout_sha256: &str,
        stderr_sha256: Option<&str>,
    ) -> Self {
        let mut hasher = Sha256::new();
        update_len_prefixed(&mut hasher, b"context-engine:artifact-id:v1");
        update_len_prefixed(&mut hasher, scope.workspace_scope_id.as_str().as_bytes());
        update_len_prefixed(&mut hasher, scope.session_id.as_str().as_bytes());
        update_len_prefixed(&mut hasher, captured_at_rfc3339.as_bytes());
        hasher.update(sequence_or_nonce.to_le_bytes());
        update_len_prefixed(&mut hasher, stdout_sha256.as_bytes());
        update_len_prefixed(&mut hasher, stderr_sha256.unwrap_or("").as_bytes());
        let digest = hex::encode(hasher.finalize());
        Self(format!("{}{digest}", Self::PREFIX))
    }

    /// Mints an [`ArtifactId`] from `(workspace_scope, session_id, seed_bytes)`.
    #[must_use]
    pub fn mint_from_seed(
        workspace_scope: &WorkspaceScopeId,
        session_id: &SessionId,
        seed_bytes: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        update_len_prefixed(&mut hasher, b"context-engine:artifact-seed:v1");
        update_len_prefixed(&mut hasher, workspace_scope.as_str().as_bytes());
        update_len_prefixed(&mut hasher, session_id.as_str().as_bytes());
        update_len_prefixed(&mut hasher, seed_bytes);
        let digest = hex::encode(hasher.finalize());
        Self(format!("{}{digest}", Self::PREFIX))
    }

    /// Parses and validates an opaque `a_<64-lowercase-hex>` [`ArtifactId`].
    pub fn parse(raw: &str) -> Result<Self> {
        let Some(hex_part) = raw.strip_prefix(Self::PREFIX) else {
            return Err(ContextError::InvalidArtifactId {
                artifact_id: raw.to_string(),
                reason: "artifact id must start with 'a_'".to_string(),
            });
        };

        if hex_part.len() != Self::HEX_LEN || !is_lowercase_hex(hex_part) {
            return Err(ContextError::InvalidArtifactId {
                artifact_id: raw.to_string(),
                reason: "artifact id must contain 'a_' followed by 64 lowercase hex characters"
                    .to_string(),
            });
        }

        Ok(Self(raw.to_string()))
    }

    /// Verifies that this artifact's stored `(workspace_scope_id, session_id)` matches `caller_scope`.
    pub fn verify_binding(
        &self,
        stored_workspace: &WorkspaceScopeId,
        stored_session: &SessionId,
        caller_scope: &BoundScope,
    ) -> Result<()> {
        caller_scope.verify_exact_scope(stored_workspace, stored_session)
    }

    /// Verifies workspace-level authorization when a tool explicitly queries across sessions
    /// within the same server-bound workspace.
    pub fn verify_workspace_binding(
        &self,
        stored_workspace: &WorkspaceScopeId,
        caller_workspace: &WorkspaceScopeId,
    ) -> Result<()> {
        if stored_workspace != caller_workspace {
            return Err(ContextError::ScopeViolation {
                expected_workspace: caller_workspace.as_str().to_string(),
                actual_workspace: stored_workspace.as_str().to_string(),
                detail: format!("artifact '{}' does not belong to bound workspace", self.0),
            });
        }
        Ok(())
    }

    /// Returns the full `a_<64-hex>` string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the 64-character lowercase SHA-256 hex digest without the `a_` prefix.
    #[must_use]
    pub fn hex_digest(&self) -> &str {
        &self.0[Self::PREFIX.len()..]
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ArtifactId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u64;
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

fn is_lowercase_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn normalize_canonical_path_for_hash(path: &str) -> String {
    let stripped = path.strip_prefix(r"\\?\").unwrap_or(path);
    let mut chars: Vec<char> = stripped.chars().collect();

    // Normalize Windows drive letter (`d:\...` -> `D:\...`) for deterministic scope hashing.
    if chars.len() >= 2 && chars[0].is_ascii_alphabetic() && chars[1] == ':' {
        chars[0] = chars[0].to_ascii_uppercase();
    }

    let mut normalized: String = chars.into_iter().collect();
    while normalized.len() > 3 && (normalized.ends_with('\\') || normalized.ends_with('/')) {
        normalized.pop();
    }
    normalized
}
