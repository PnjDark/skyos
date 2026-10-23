use anyhow::{bail, Context, Result};
use kernel::artifacts::registry::{Artifact, ArtifactRegistry, ArtifactType};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{Capability, PolicyDecision, ToolInvocationRequest};
use kernel::tasks::state::TaskState;
use kernel::tasks::store::TaskStore;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

use crate::operations::OperationSpec;

pub struct TrustedExecutor<'a> {
    task_store: &'a TaskStore,
    event_bus: &'a EventBus,
    artifact_registry: &'a mut ArtifactRegistry,
    grant_issuer: &'a GrantIssuer,
}

impl<'a> TrustedExecutor<'a> {
    pub fn new(
        task_store: &'a TaskStore,
        event_bus: &'a EventBus,
        artifact_registry: &'a mut ArtifactRegistry,
        grant_issuer: &'a GrantIssuer,
    ) -> Self {
        Self {
            task_store,
            event_bus,
            artifact_registry,
            grant_issuer,
        }
    }

    // Hardened path containment check preventing traversal (..) and absolute path escapes, with symlink resolution.
    fn validate_and_resolve_target_path(
        workspace_root: &Path,
        relative_path: &Path,
    ) -> Result<PathBuf> {
        // Disallow absolute paths
        if relative_path.is_absolute() {
            bail!(
                "Absolute paths are forbidden in workspace operations: {:?}",
                relative_path
            );
        }

        // Disallow any parent directory components (..)
        for component in relative_path.components() {
            if matches!(component, Component::ParentDir) {
                bail!(
                    "Path traversal (..) forbidden in workspace relative path: {:?}",
                    relative_path
                );
            }
        }

        // Canonicalize the workspace root – it must exist
        let canonical_workspace = std::fs::canonicalize(workspace_root).with_context(|| {
            format!(
                "Invalid or nonexistent workspace path: {:?}",
                workspace_root
            )
        })?;

        // Build the intended target path
        let target_path = canonical_workspace.join(relative_path);

        // Resolve the physical path to guard against symlink escapes.
        // If the target exists, canonicalize it directly; otherwise canonicalize its existing parent.
        let check_path = if target_path.exists() {
            target_path.canonicalize()?
        } else if let Some(parent) = target_path.parent() {
            if parent.exists() {
                parent
                    .canonicalize()?
                    .join(target_path.file_name().unwrap())
            } else {
                // Neither target nor parent exists – use the intended path for lexical check only
                target_path.clone()
            }
        } else {
            target_path.clone()
        };

        // Ensure the resolved path is still within the workspace root
        if !check_path.starts_with(&canonical_workspace) {
            bail!(
                "Symlink or path traversal escape detected: {:?} escapes workspace {:?}",
                check_path,
                canonical_workspace
            );
        }

        Ok(target_path)
    }

    pub fn execute_operation(
        &mut self,
        task_id: Uuid,
        agent_id: &str,
        workspace_root: &Path,
        op: OperationSpec,
    ) -> Result<Artifact> {
        // 1. Fetch and validate task state transition eligibility
        let task = self
            .task_store
            .get_task(&task_id)?
            .context("Task not found in store")?;

        // Only new or ready tasks are eligible for execution.
        if task.state != TaskState::Created && task.state != TaskState::Ready {
            bail!(
                "Task {} in state '{:?}' is not eligible for execution",
                task_id,
                task.state
            );
        }

        match op {
            OperationSpec::WriteSnapshot {
                relative_path,
                content_bytes,
            } => {
                // 2. HARDENED BOUNDARY: Validate and resolve containment before I/O
                let target_path =
                    Self::validate_and_resolve_target_path(workspace_root, &relative_path)?;
                let canonical_workspace = std::fs::canonicalize(workspace_root)?;

                // 3. Advance through the task state machine before running the operation.
                let mut current_state = task.state;
                if current_state == TaskState::Created {
                    self.task_store.transition_state(
                        task_id,
                        TaskState::Created,
                        TaskState::Ready,
                    )?;
                    current_state = TaskState::Ready;
                }
                self.task_store
                    .transition_state(task_id, current_state, TaskState::Claimed)?;
                self.task_store.transition_state(
                    task_id,
                    TaskState::Claimed,
                    TaskState::Running,
                )?;

                // 4. Issue short-lived CapabilityGrant
                let grant = self.grant_issuer.issue_grant(
                    agent_id,
                    task_id,
                    vec![
                        Capability::FileSystemRead {
                            root: canonical_workspace.clone(),
                        },
                        Capability::FileSystemWrite {
                            root: canonical_workspace.clone(),
                        },
                    ],
                    None,
                );

                // 5. Evaluate authorization via Policy Engine
                let req = ToolInvocationRequest::FileSystemWrite {
                    requested_path: target_path.clone(),
                };

                let policy_engine = PolicyEngine::new(Some(self.event_bus));
                let decision = policy_engine.evaluate(&grant, &req);

                match decision {
                    PolicyDecision::Allow { .. } => {
                        // 6. Execute bounded file write
                        if let Some(parent) = target_path.parent() {
                            // Ensure parent is still inside workspace
                            if parent.starts_with(&canonical_workspace) {
                                std::fs::create_dir_all(parent)?;
                            } else {
                                self.task_store.transition_state(
                                    task_id,
                                    TaskState::Running,
                                    TaskState::Failed,
                                )?;
                                bail!("Parent directory escapes canonical workspace");
                            }
                        }

                        std::fs::write(&target_path, &content_bytes)?;

                        // 7. ARTIFACT CONTRACT PROOF: Read back bytes from disk to independently verify disk write
                        let written_bytes = std::fs::read(&target_path)
                            .context("Failed to read back written file for CAS verification")?;

                        if written_bytes != content_bytes {
                            self.task_store.transition_state(
                                task_id,
                                TaskState::Running,
                                TaskState::Failed,
                            )?;
                            bail!("Written snapshot bytes did not match the requested content");
                        }

                        let filename = relative_path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| "snapshot.bin".to_string());

                        // 8. Register verified bytes in Content-Addressable Storage (CAS)
                        let task_id_str = task_id.to_string();
                        let artifact = self.artifact_registry.register_file_artifact(
                            &target_path,
                            Some(task_id_str.as_str()),
                            ArtifactType::Snapshot,
                            None,
                            serde_json::json!({
                                "workspace": canonical_workspace,
                                "target_path": target_path,
                                "file_name": filename,
                                "verified_on_disk": true,
                            }),
                        )?;

                        // 9. Transition task to Completed
                        self.task_store.transition_state(
                            task_id,
                            TaskState::Running,
                            TaskState::Completed,
                        )?;

                        Ok(artifact)
                    }
                    PolicyDecision::Deny { reason } => {
                        self.task_store.transition_state(
                            task_id,
                            TaskState::Running,
                            TaskState::Failed,
                        )?;
                        bail!("Policy Engine denied operation: {}", reason);
                    }
                }
            }
        }
    }
}
