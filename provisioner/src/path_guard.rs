use crate::errors::ProvisionError;
use std::path::{Path, PathBuf};

/// Canonical path containment guard.
///
/// All paths are canonicalized with `dunce` (Windows-UNC-safe) and verified to
/// live inside `sandbox_root`. Traversals (`..`), symlinks resolving outside
/// the sandbox, and non-existent targets whose *existing* ancestors escape the
/// sandbox are rejected **before** any filesystem mutation.
pub struct PathGuard {
    sandbox_root: PathBuf,
}

impl PathGuard {
    pub fn new(sandbox_root: impl AsRef<Path>) -> Result<Self, ProvisionError> {
        let canonical_sandbox =
            dunce::canonicalize(sandbox_root.as_ref()).map_err(ProvisionError::Io)?;
        Ok(Self {
            sandbox_root: canonical_sandbox,
        })
    }

    /// Resolve `target` (relative or absolute) and verify it stays inside the
    /// sandbox. For destinations that do not exist yet, the nearest existing
    /// ancestor is canonicalized and the remaining tail re-attached.
    pub fn sanitize_and_verify(&self, target: &Path) -> Result<PathBuf, ProvisionError> {
        let traversal_err = || ProvisionError::PathTraversalViolation {
            target: target.to_path_buf(),
            sandbox_root: self.sandbox_root.clone(),
        };

        let joined = if target.is_absolute() {
            target.to_path_buf()
        } else {
            self.sandbox_root.join(target)
        };

        // Find the nearest existing ancestor and canonicalize it.
        let mut existing_ancestor = joined.as_path();
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        loop {
            if existing_ancestor.exists() {
                break;
            }
            match existing_ancestor.parent() {
                Some(parent) => {
                    if let Some(name) = existing_ancestor.file_name() {
                        tail.push(name.to_os_string());
                    }
                    existing_ancestor = parent;
                }
                None => return Err(traversal_err()),
            }
        }

        let canonical_base = dunce::canonicalize(existing_ancestor).map_err(|_| traversal_err())?;
        let mut resolved = canonical_base;
        for component in tail.iter().rev() {
            resolved.push(component);
        }

        if !resolved.starts_with(&self.sandbox_root) {
            return Err(traversal_err());
        }

        // Reject symlinks (including intermediate links) that resolve outside
        // the sandbox. `symlink_metadata` distinguinks links from regular nodes.
        let mut cursor: &Path = &resolved;
        loop {
            if cursor
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                let link_target = std::fs::read_link(cursor).map_err(ProvisionError::Io)?;
                let absolute_target = if link_target.is_absolute() {
                    link_target
                } else {
                    cursor
                        .parent()
                        .unwrap_or(&self.sandbox_root)
                        .join(link_target)
                };
                let canonical_link = dunce::canonicalize(&absolute_target).map_err(|_| {
                    ProvisionError::SymlinkEscape {
                        path: cursor.to_path_buf(),
                    }
                })?;
                if !canonical_link.starts_with(&self.sandbox_root) {
                    return Err(ProvisionError::SymlinkEscape {
                        path: cursor.to_path_buf(),
                    });
                }
            }
            match cursor.parent() {
                Some(parent) if parent.starts_with(&self.sandbox_root) => cursor = parent,
                _ => break,
            }
        }

        Ok(resolved)
    }

    pub fn sandbox_root(&self) -> &Path {
        &self.sandbox_root
    }
}
