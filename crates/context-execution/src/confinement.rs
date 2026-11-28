//! Canonical workspace path confinement, symlink/junction escape rejection,
//! sensitive file blocking, and TOCTOU-guarded file opening.

use std::fs::{self, File, Metadata};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use context_core::{BoundScope, ContextError, ExecutionPolicyConfig, Result};
use serde::{Deserialize, Serialize};

/// A filesystem path verified to reside canonically inside [`BoundScope::workspace_root`]
/// and permitted by [`ExecutionPolicyConfig::ensure_non_sensitive_path`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinedPath {
    /// Canonical filesystem path inside `BoundScope::workspace_root` (without `\\?\` prefix).
    pub canonical: PathBuf,
    /// Deterministic forward-slash path relative to `BoundScope::workspace_root` (`"."` for root).
    pub relative: String,
}

impl ConfinedPath {
    /// Returns the canonical [`Path`].
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.canonical
    }
}

/// Resolves `requested` (relative to `scope.workspace_root` or absolute) into a [`ConfinedPath`].
///
/// Security checks enforced:
/// 1. Rejects empty paths or paths containing NUL bytes.
/// 2. Walks components step-by-step from the canonical workspace root (or absolute prefix),
///    resolving every existing prefix via `dunce::canonicalize` so symlinks and Windows NTFS
///    junctions are dereferenced immediately—even when leaf components do not exist yet.
/// 3. Rejects dangling symlinks/reparse points whose target cannot be canonically verified
///    inside `scope.workspace_root`.
/// 4. Verifies the final canonical path stays strictly inside `scope.workspace_root`.
/// 5. Enforces [`ExecutionPolicyConfig::ensure_non_sensitive_path`] against both the resolved
///    workspace-relative path and (when relative) the caller-supplied lexical path so neither
///    `safe_link -> .env` nor `.env_link -> safe.txt` can bypass sensitive file blocks.
pub fn resolve_path_in_scope(
    scope: &BoundScope,
    policy: &ExecutionPolicyConfig,
    requested: &Path,
) -> Result<ConfinedPath> {
    let raw_display = requested.display().to_string();
    if raw_display.is_empty() {
        return Err(ContextError::PathEscape {
            path: raw_display,
            workspace_root: scope.workspace_root.display().to_string(),
            reason: "path cannot be empty".to_string(),
        });
    }
    if raw_display.contains('\0') {
        return Err(ContextError::PathEscape {
            path: raw_display,
            workspace_root: scope.workspace_root.display().to_string(),
            reason: "path must not contain NUL bytes".to_string(),
        });
    }

    let canonical_root = canonicalize_workspace_root(&scope.workspace_root)?;
    let simplified_requested = dunce::simplified(requested);

    let resolved = walk_and_canonicalize(simplified_requested, &canonical_root, &raw_display)?;

    let Some(relative) = relative_within_workspace(&resolved, &canonical_root) else {
        return Err(ContextError::PathEscape {
            path: raw_display,
            workspace_root: canonical_root.display().to_string(),
            reason: format!(
                "resolved path '{}' is outside workspace root",
                resolved.display()
            ),
        });
    };

    // Enforce sensitive-path denylist on both canonical workspace-relative path and
    // relative lexical input (catching symlinks in either direction).
    if relative != "." {
        policy.ensure_non_sensitive_path(Path::new(&relative))?;
    }
    if simplified_requested.is_relative() {
        policy.ensure_non_sensitive_path(simplified_requested)?;
    } else if let Some(lexical_rel) =
        relative_within_workspace(simplified_requested, &canonical_root)
    {
        if lexical_rel != "." {
            policy.ensure_non_sensitive_path(Path::new(&lexical_rel))?;
        }
    }

    Ok(ConfinedPath {
        canonical: resolved,
        relative,
    })
}

/// Resolves an optional working directory (`None` defaults to `scope.workspace_root`) and verifies
/// that it exists on disk as a directory inside `scope.workspace_root`.
pub fn resolve_cwd_in_scope(
    scope: &BoundScope,
    policy: &ExecutionPolicyConfig,
    requested_cwd: Option<&Path>,
) -> Result<ConfinedPath> {
    let target = match requested_cwd {
        None => Path::new("."),
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
    };

    let confined = resolve_path_in_scope(scope, policy, target)?;

    let meta = fs::metadata(&confined.canonical).map_err(|err| match err.kind() {
        ErrorKind::NotFound => ContextError::InvalidWorkspacePath {
            path: confined.canonical.display().to_string(),
            reason: "working directory does not exist".to_string(),
        },
        _ => ContextError::Io(err),
    })?;

    if !meta.is_dir() {
        return Err(ContextError::InvalidWorkspacePath {
            path: confined.canonical.display().to_string(),
            reason: "working directory path is not a directory".to_string(),
        });
    }

    // Re-canonicalize existing directory to guarantee zero post-check drift.
    let recanon = dunce::canonicalize(&confined.canonical)?;
    let canonical_root = canonicalize_workspace_root(&scope.workspace_root)?;
    let Some(relative) = relative_within_workspace(&recanon, &canonical_root) else {
        return Err(ContextError::PathEscape {
            path: target.display().to_string(),
            workspace_root: canonical_root.display().to_string(),
            reason: "working directory escaped workspace root".to_string(),
        });
    };
    if relative != "." {
        policy.ensure_non_sensitive_path(Path::new(&relative))?;
    }

    Ok(ConfinedPath {
        canonical: recanon,
        relative,
    })
}

/// Resolves `requested_file` inside `scope.workspace_root` and verifies that it exists as a
/// regular file (not a directory or special device).
pub fn resolve_existing_file_in_scope(
    scope: &BoundScope,
    policy: &ExecutionPolicyConfig,
    requested_file: &Path,
) -> Result<ConfinedPath> {
    let confined = resolve_path_in_scope(scope, policy, requested_file)?;
    let meta = fs::metadata(&confined.canonical).map_err(|err| match err.kind() {
        ErrorKind::NotFound => ContextError::Io(err),
        _ => ContextError::Io(err),
    })?;

    if !meta.is_file() {
        return Err(ContextError::InvalidWorkspacePath {
            path: confined.canonical.display().to_string(),
            reason: "path must refer to a regular file".to_string(),
        });
    }

    Ok(confined)
}

/// Opens a regular file inside `scope.workspace_root` with pre-open confinement validation
/// and post-open metadata/re-canonicalization TOCTOU verification.
pub fn open_confined_file_sync(
    scope: &BoundScope,
    policy: &ExecutionPolicyConfig,
    requested_file: &Path,
) -> Result<(File, ConfinedPath)> {
    let confined = resolve_existing_file_in_scope(scope, policy, requested_file)?;
    let pre_meta = fs::symlink_metadata(&confined.canonical)?;
    if pre_meta.file_type().is_symlink() {
        return Err(ContextError::PathEscape {
            path: requested_file.display().to_string(),
            workspace_root: scope.workspace_root.display().to_string(),
            reason: "canonical target unexpectedly resolved to an unexpanded symlink".to_string(),
        });
    }

    let file = File::open(&confined.canonical)?;
    let opened_meta = file.metadata()?;
    if !opened_meta.is_file() {
        return Err(ContextError::InvalidWorkspacePath {
            path: confined.canonical.display().to_string(),
            reason: "opened handle is not a regular file".to_string(),
        });
    }

    // Post-open TOCTOU verification while holding `file` open.
    let canonical_root = canonicalize_workspace_root(&scope.workspace_root)?;
    let post_canon =
        dunce::canonicalize(&confined.canonical).map_err(|err| ContextError::PathEscape {
            path: requested_file.display().to_string(),
            workspace_root: canonical_root.display().to_string(),
            reason: format!("post-open canonicalization failed during TOCTOU check: {err}"),
        })?;

    let Some(post_relative) = relative_within_workspace(&post_canon, &canonical_root) else {
        return Err(ContextError::PathEscape {
            path: requested_file.display().to_string(),
            workspace_root: canonical_root.display().to_string(),
            reason: "file target escaped workspace root during open (TOCTOU detected)".to_string(),
        });
    };

    if post_relative != "." {
        policy.ensure_non_sensitive_path(Path::new(&post_relative))?;
    }

    let post_symlink_meta = fs::symlink_metadata(&post_canon)?;
    verify_same_file_identity(
        &pre_meta,
        &opened_meta,
        &post_symlink_meta,
        requested_file,
        &canonical_root,
    )?;

    Ok((
        file,
        ConfinedPath {
            canonical: post_canon,
            relative: post_relative,
        },
    ))
}

/// Async counterpart to [`open_confined_file_sync`], returning a [`tokio::fs::File`] and
/// verified [`ConfinedPath`].
pub async fn open_confined_file(
    scope: &BoundScope,
    policy: &ExecutionPolicyConfig,
    requested_file: &Path,
) -> Result<(tokio::fs::File, ConfinedPath)> {
    let scope_cloned = scope.clone();
    let policy_cloned = policy.clone();
    let path_cloned = requested_file.to_path_buf();

    let (std_file, confined) = tokio::task::spawn_blocking(move || {
        open_confined_file_sync(&scope_cloned, &policy_cloned, &path_cloned)
    })
    .await
    .map_err(|join_err| {
        ContextError::Io(std::io::Error::other(format!(
            "confined file open task panicked: {join_err}"
        )))
    })??;

    Ok((tokio::fs::File::from_std(std_file), confined))
}

fn canonicalize_workspace_root(root: &Path) -> Result<PathBuf> {
    dunce::canonicalize(root).map_err(|err| ContextError::InvalidWorkspacePath {
        path: root.display().to_string(),
        reason: err.to_string(),
    })
}

fn walk_and_canonicalize(
    requested: &Path,
    canonical_root: &Path,
    raw_display: &str,
) -> Result<PathBuf> {
    let mut current = if requested.is_absolute() {
        PathBuf::new()
    } else {
        canonical_root.to_path_buf()
    };

    for comp in requested.components() {
        match comp {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
            }
            Component::RootDir => {
                current.push(comp.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if fs::symlink_metadata(&current).is_ok() {
                    current = resolve_existing_entry(&current, canonical_root, raw_display)?;
                }
                if !current.pop() {
                    return Err(ContextError::PathEscape {
                        path: raw_display.to_string(),
                        workspace_root: canonical_root.display().to_string(),
                        reason: "parent directory traversal ('..') escaped filesystem root"
                            .to_string(),
                    });
                }
            }
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        let was_reparse_or_link = is_symlink_or_reparse(&meta);
                        let canon = resolve_existing_entry(&current, canonical_root, raw_display)?;
                        if was_reparse_or_link
                            && relative_within_workspace(&canon, canonical_root).is_none()
                        {
                            return Err(ContextError::PathEscape {
                                path: raw_display.to_string(),
                                workspace_root: canonical_root.display().to_string(),
                                reason: format!(
                                    "symlink or junction '{}' resolves outside workspace to '{}'",
                                    current.display(),
                                    canon.display()
                                ),
                            });
                        }
                        current = canon;
                    }
                    Err(err) if err.kind() == ErrorKind::NotFound => {
                        // Non-existent leaf/intermediate directory: keep lexical name attached
                        // to the already-canonicalized ancestor.
                    }
                    Err(err) => return Err(ContextError::Io(err)),
                }
            }
        }
    }

    Ok(current)
}

fn resolve_existing_entry(
    entry: &Path,
    canonical_root: &Path,
    raw_display: &str,
) -> Result<PathBuf> {
    match dunce::canonicalize(entry) {
        Ok(canon) => Ok(canon),
        Err(err) if err.kind() == ErrorKind::NotFound => Err(ContextError::PathEscape {
            path: raw_display.to_string(),
            workspace_root: canonical_root.display().to_string(),
            reason: format!(
                "dangling or unresolvable symlink/reparse point at '{}'",
                entry.display()
            ),
        }),
        Err(err) => Err(ContextError::Io(err)),
    }
}

#[cfg(windows)]
fn is_symlink_or_reparse(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(windows))]
fn is_symlink_or_reparse(meta: &Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Checks whether `candidate` is equal to or a descendant of `workspace_root`, returning
/// the forward-slash relative path (`"."` when equal) or `None` when outside.
#[must_use]
pub fn relative_within_workspace(candidate: &Path, workspace_root: &Path) -> Option<String> {
    let cand = dunce::simplified(candidate);
    let root = dunce::simplified(workspace_root);

    let mut cand_comps = cand.components();
    for root_comp in root.components() {
        let cand_comp = cand_comps.next()?;
        if !components_equal(cand_comp, root_comp) {
            return None;
        }
    }

    let mut parts: Vec<String> = Vec::new();
    for rest in cand_comps {
        match rest {
            Component::CurDir => {}
            Component::Normal(os) => parts.push(os.to_string_lossy().into_owned()),
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return None,
        }
    }

    if parts.is_empty() {
        Some(".".to_string())
    } else {
        Some(parts.join("/"))
    }
}

fn components_equal(a: Component<'_>, b: Component<'_>) -> bool {
    #[cfg(windows)]
    {
        match (a, b) {
            (Component::Prefix(pa), Component::Prefix(pb)) => pa
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&pb.as_os_str().to_string_lossy()),
            (Component::RootDir, Component::RootDir) => true,
            (Component::CurDir, Component::CurDir) => true,
            (Component::ParentDir, Component::ParentDir) => true,
            (Component::Normal(na), Component::Normal(nb)) => {
                let sa = na.to_string_lossy();
                let sb = nb.to_string_lossy();
                sa == sb || sa.to_lowercase() == sb.to_lowercase()
            }
            _ => false,
        }
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

#[cfg(unix)]
fn verify_same_file_identity(
    pre_meta: &Metadata,
    opened_meta: &Metadata,
    post_meta: &Metadata,
    requested_file: &Path,
    canonical_root: &Path,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if pre_meta.dev() != opened_meta.dev()
        || pre_meta.ino() != opened_meta.ino()
        || opened_meta.dev() != post_meta.dev()
        || opened_meta.ino() != post_meta.ino()
    {
        return Err(ContextError::PathEscape {
            path: requested_file.display().to_string(),
            workspace_root: canonical_root.display().to_string(),
            reason: "file inode/device changed during open (TOCTOU swap detected)".to_string(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_same_file_identity(
    pre_meta: &Metadata,
    opened_meta: &Metadata,
    post_meta: &Metadata,
    requested_file: &Path,
    canonical_root: &Path,
) -> Result<()> {
    if is_symlink_or_reparse(post_meta) {
        return Err(ContextError::PathEscape {
            path: requested_file.display().to_string(),
            workspace_root: canonical_root.display().to_string(),
            reason: "canonical file became a reparse point during open (TOCTOU swap detected)"
                .to_string(),
        });
    }

    if let (Ok(pre_created), Ok(open_created), Ok(post_created)) = (
        pre_meta.created(),
        opened_meta.created(),
        post_meta.created(),
    ) {
        if pre_created != open_created || open_created != post_created {
            return Err(ContextError::PathEscape {
                path: requested_file.display().to_string(),
                workspace_root: canonical_root.display().to_string(),
                reason: "file creation timestamp changed during open (TOCTOU replacement detected)"
                    .to_string(),
            });
        }
    }

    Ok(())
}
