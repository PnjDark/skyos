/// Phase 5.2 — Fresh Grant Re-Authorization.
///
/// Recovery does not resurrect grants.  A grant that existed before a crash is
/// evidence that authorization once happened; it is never evidence that
/// authorization still holds.  When a `RetryReady` checkpoint is about to be
/// executed again, `RecoveryAuthorizer` rebuilds the authorization from
/// durable state:
///
/// 1. a checkpoint that is actually retry-eligible identifies the invocation;
/// 2. the persisted `AuthorizationContext` supplies the capability *intent*
///    that was recorded before dispatch;
/// 3. the **current** `AuthorizationPolicy` decides whether that intent is
///    still permitted (expiry, revocation, policy drift included);
/// 4. a fresh, time-bounded grant is minted only for exactly that intent;
/// 5. the decision is written to `recovery_authorization_decisions` and to the
///    event ledger — and a decision that cannot be audited yields no grant.
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;
use uuid::Uuid;

use crate::events::{EventBus, EventError};
use crate::permissions::engine::PolicyEngine;
use crate::permissions::issuer::GrantIssuer;
use crate::permissions::policy::{AuthorizationPolicy, PolicyDrift};
use crate::permissions::types::{Capability, CapabilityGrant, CapabilityKind};
use crate::persistence::db::{DatabaseConnectionPool, DatabaseError};
use crate::persistence::migrations::apply_recovery_schema;
use crate::tasks::checkpoint::{
    CheckpointError, CheckpointStatus, CheckpointStore, TaskCheckpoint,
};
use crate::tasks::state::TaskState;
use crate::tasks::store::{TaskStore, TaskStoreError};

/// Lifetime of a recovery-issued grant.  Deliberately short: it authorizes one
/// resumed step, not the remainder of the task's life.
pub const RECOVERY_GRANT_TTL_SECONDS: i64 = 3600;

pub const EVENT_REAUTHORIZATION_GRANTED: &str = "RecoveryAuthorizationGranted";
pub const EVENT_REAUTHORIZATION_DENIED: &str = "RecoveryAuthorizationDenied";

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("task store error: {0}")]
    TaskStore(#[from] TaskStoreError),
    #[error("event emission failed: {0}")]
    Event(#[from] EventError),
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),
    #[error("task {0} not found")]
    TaskNotFound(Uuid),
    #[error("checkpoint {task_id}/{step_number} not found")]
    CheckpointNotFound { task_id: Uuid, step_number: usize },
    #[error("checkpoint {task_id}/{step_number} is {status}, not RetryReady")]
    NotRetryEligible {
        task_id: Uuid,
        step_number: usize,
        status: String,
    },
    #[error(
        "checkpoint {task_id}/{step_number} has no recorded invocation identity; \
         refusing to authorize an unidentifiable retry"
    )]
    IncompleteCheckpoint { task_id: Uuid, step_number: usize },
    #[error("task {task_id} is {state}; it must be re-queued before re-authorization")]
    TaskNotRecoverable { task_id: Uuid, state: String },
    #[error(
        "agent identity mismatch: checkpoint records '{recorded}', request claims '{requested}'"
    )]
    AgentIdentityMismatch { recorded: String, requested: String },
    #[error(
        "no persisted authorization context for {task_id}/{step_number}; \
         authorization cannot be re-established"
    )]
    MissingAuthorizationContext { task_id: Uuid, step_number: usize },
    #[error(
        "capability requirements for '{tool_id}/{operation_id}' cannot be derived from the \
         tool manifest ({task_id}/{step_number}); refusing to authorize an operation of \
         unknown authority"
    )]
    CapabilityRequirementsUnderivable {
        task_id: Uuid,
        step_number: usize,
        tool_id: String,
        operation_id: String,
    },
    #[error(
        "the recorded capability intent for {task_id}/{step_number} does not cover the \
         pending operation, which requires {required}"
    )]
    IntentDoesNotCoverOperation {
        task_id: Uuid,
        step_number: usize,
        required: CapabilityKind,
    },
    #[error("authorization refused for {task_id}/{step_number}: {reason}")]
    Refused {
        task_id: Uuid,
        step_number: usize,
        reason: String,
    },
    #[error("authorization decision could not be durably recorded: {0}")]
    AuditFailure(String),
}

// ── Persisted authorization context ──────────────────────────────────────────

/// What the runtime knew it was authorized to do when it dispatched a step.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationContext {
    pub task_id: Uuid,
    pub step_number: usize,
    pub agent_id: String,
    pub capabilities: Vec<Capability>,
    /// Capability family the pending operation requires, derived by the runtime
    /// from the tool manifest.  `None` means the requirement could not be
    /// derived, and the retry is refused rather than guessed.
    pub required_capability: Option<CapabilityKind>,
    pub policy_id: String,
    pub policy_version: u64,
    pub recorded_at: String,
}

/// Append-only record of one re-authorization attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationDecisionRecord {
    pub decision_id: Uuid,
    pub task_id: Uuid,
    pub step_number: usize,
    pub agent_id: String,
    pub granted: bool,
    pub reason: String,
    pub grant_id: Option<Uuid>,
    pub requested_capabilities: Vec<Capability>,
    pub policy_id: String,
    pub policy_version: u64,
    pub decided_at: String,
}

/// Storage for the two Phase 5.2 tables.
#[derive(Debug, Clone)]
pub struct AuthorizationStore {
    pool: DatabaseConnectionPool,
}

impl AuthorizationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthorizationError> {
        let pool = DatabaseConnectionPool::open(path)?;
        let conn = pool.connection()?;
        apply_recovery_schema(&conn)?;
        Ok(Self { pool })
    }

    pub fn connection(&self) -> Result<Connection, AuthorizationError> {
        Ok(self.pool.connection()?)
    }

    /// Persist the capability intent for a step.  Called inside the same
    /// transaction as the `Pending` checkpoint write.
    pub fn record_with_connection(
        conn: &Connection,
        context: &AuthorizationContext,
    ) -> Result<(), AuthorizationError> {
        let capabilities = serde_json::to_string(&context.capabilities)?;
        conn.execute(
            "INSERT OR REPLACE INTO task_authorization_context \
             (task_id, step_number, agent_id, capabilities, required_capability, policy_id, \
              policy_version, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                context.task_id.to_string(),
                context.step_number as i64,
                &context.agent_id,
                capabilities,
                context.required_capability.map(|kind| kind.as_str()),
                &context.policy_id,
                context.policy_version as i64,
                &context.recorded_at,
            ],
        )?;
        Ok(())
    }

    pub fn get(
        &self,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<Option<AuthorizationContext>, AuthorizationError> {
        let conn = self.pool.connection()?;
        let row = conn
            .query_row(
                "SELECT task_id, step_number, agent_id, capabilities, required_capability, \
                        policy_id, policy_version, recorded_at \
                 FROM task_authorization_context WHERE task_id = ?1 AND step_number = ?2",
                rusqlite::params![task_id.to_string(), step_number as i64],
                |row| {
                    Ok((
                        row.get::<_, String>("task_id")?,
                        row.get::<_, i64>("step_number")?,
                        row.get::<_, String>("agent_id")?,
                        row.get::<_, String>("capabilities")?,
                        row.get::<_, Option<String>>("required_capability")?,
                        row.get::<_, String>("policy_id")?,
                        row.get::<_, i64>("policy_version")?,
                        row.get::<_, String>("recorded_at")?,
                    ))
                },
            )
            .optional()?;

        let Some((
            task_id_str,
            step,
            agent_id,
            capabilities,
            required_capability,
            policy_id,
            version,
            recorded_at,
        )) = row
        else {
            return Ok(None);
        };

        Ok(Some(AuthorizationContext {
            task_id: Uuid::parse_str(&task_id_str)?,
            step_number: step as usize,
            agent_id,
            capabilities: serde_json::from_str(&capabilities)?,
            required_capability: required_capability
                .as_deref()
                .and_then(CapabilityKind::from_name),
            policy_id,
            policy_version: version as u64,
            recorded_at,
        }))
    }

    pub fn record_decision_with_connection(
        conn: &Connection,
        decision: &AuthorizationDecisionRecord,
    ) -> Result<(), AuthorizationError> {
        let capabilities = serde_json::to_string(&decision.requested_capabilities)?;
        conn.execute(
            "INSERT INTO recovery_authorization_decisions \
             (decision_id, task_id, step_number, agent_id, outcome, reason, grant_id, \
              requested_capabilities, policy_id, policy_version, decided_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                decision.decision_id.to_string(),
                decision.task_id.to_string(),
                decision.step_number as i64,
                &decision.agent_id,
                if decision.granted {
                    "Granted"
                } else {
                    "Denied"
                },
                &decision.reason,
                decision.grant_id.map(|id| id.to_string()),
                capabilities,
                &decision.policy_id,
                decision.policy_version as i64,
                &decision.decided_at,
            ],
        )?;
        Ok(())
    }

    pub fn record_decision(
        &self,
        decision: &AuthorizationDecisionRecord,
    ) -> Result<(), AuthorizationError> {
        let conn = self.pool.connection()?;
        Self::record_decision_with_connection(&conn, decision)
    }

    /// Read back every decision for `task_id`, oldest first.
    pub fn list_decisions(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<AuthorizationDecisionRecord>, AuthorizationError> {
        let conn = self.pool.connection()?;
        let mut stmt = conn.prepare(
            "SELECT decision_id, task_id, step_number, agent_id, outcome, reason, grant_id, \
                    requested_capabilities, policy_id, policy_version, decided_at \
             FROM recovery_authorization_decisions WHERE task_id = ?1 \
             ORDER BY decided_at ASC, rowid ASC",
        )?;
        let rows = stmt.query_map([task_id.to_string()], |row| {
            Ok((
                row.get::<_, String>("decision_id")?,
                row.get::<_, i64>("step_number")?,
                row.get::<_, String>("agent_id")?,
                row.get::<_, String>("outcome")?,
                row.get::<_, String>("reason")?,
                row.get::<_, Option<String>>("grant_id")?,
                row.get::<_, String>("requested_capabilities")?,
                row.get::<_, String>("policy_id")?,
                row.get::<_, i64>("policy_version")?,
                row.get::<_, String>("decided_at")?,
            ))
        })?;

        let mut decisions = Vec::new();
        for row in rows {
            let (
                decision_id,
                step,
                agent_id,
                outcome,
                reason,
                grant_id,
                capabilities,
                policy_id,
                version,
                decided_at,
            ) = row?;
            decisions.push(AuthorizationDecisionRecord {
                decision_id: Uuid::parse_str(&decision_id)?,
                task_id,
                step_number: step as usize,
                agent_id,
                granted: outcome == "Granted",
                reason,
                grant_id: grant_id.map(|id| Uuid::parse_str(&id)).transpose()?,
                requested_capabilities: serde_json::from_str(&capabilities)?,
                policy_id,
                policy_version: version as u64,
                decided_at,
            });
        }
        Ok(decisions)
    }
}

// ── Authorizer ───────────────────────────────────────────────────────────────

/// Outcome of a successful re-authorization.
#[derive(Debug, Clone)]
pub struct RecoveryAuthorization {
    pub task_id: Uuid,
    pub step_number: usize,
    pub agent_id: String,
    pub grant: CapabilityGrant,
    pub capabilities: Vec<Capability>,
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_drift: PolicyDrift,
    pub decided_at: DateTime<Utc>,
}

/// Re-establishes authorization for an interrupted, retry-eligible invocation.
pub struct RecoveryAuthorizer<'a> {
    policy: &'a AuthorizationPolicy,
    grant_issuer: &'a GrantIssuer,
    task_store: &'a TaskStore,
    event_bus: &'a EventBus,
    checkpoint_store: &'a CheckpointStore,
    authorization_store: &'a AuthorizationStore,
}

impl<'a> RecoveryAuthorizer<'a> {
    pub fn new(
        policy: &'a AuthorizationPolicy,
        grant_issuer: &'a GrantIssuer,
        task_store: &'a TaskStore,
        event_bus: &'a EventBus,
        checkpoint_store: &'a CheckpointStore,
        authorization_store: &'a AuthorizationStore,
    ) -> Self {
        Self {
            policy,
            grant_issuer,
            task_store,
            event_bus,
            checkpoint_store,
            authorization_store,
        }
    }

    /// Re-authorize one `RetryReady` step for `requesting_agent`.
    ///
    /// Returns a fresh, narrowly scoped grant on success.  On refusal the task
    /// is failed and an audited denial is recorded; no grant is ever issued.
    pub fn reauthorize_recovery_task(
        &self,
        task_id: Uuid,
        step_number: usize,
        requesting_agent: &str,
    ) -> Result<RecoveryAuthorization, AuthorizationError> {
        // 1. The checkpoint must be retry-eligible.  `RetryReady` is a
        //    retryability verdict, never an authorization.
        let checkpoint = self.load_retry_eligible_checkpoint(task_id, step_number)?;

        // 2. Task identity and lifecycle.
        let task = self
            .task_store
            .get_task(&task_id)?
            .ok_or(AuthorizationError::TaskNotFound(task_id))?;

        if !matches!(
            task.state,
            TaskState::Running | TaskState::Ready | TaskState::Claimed
        ) {
            return Err(AuthorizationError::TaskNotRecoverable {
                task_id,
                state: task.state.to_string(),
            });
        }

        // 3. Agent identity: the checkpoint's recorded agent is authoritative.
        if checkpoint.agent_id != requesting_agent {
            let reason = format!(
                "agent identity mismatch: checkpoint records '{}', request claims '{}'",
                checkpoint.agent_id, requesting_agent
            );
            self.record_denial(task_id, step_number, requesting_agent, &[], reason.clone())?;
            return Err(AuthorizationError::AgentIdentityMismatch {
                recorded: checkpoint.agent_id,
                requested: requesting_agent.to_string(),
            });
        }

        // 4. Capability intent recorded before dispatch.
        let context = self.authorization_store.get(task_id, step_number)?.ok_or(
            AuthorizationError::MissingAuthorizationContext {
                task_id,
                step_number,
            },
        )?;

        if context.agent_id != requesting_agent || context.task_id != task_id {
            let reason = format!(
                "authorization context identity mismatch: recorded task {} agent '{}', \
                 requested task {task_id} agent '{requesting_agent}'",
                context.task_id, context.agent_id
            );
            self.record_denial(
                task_id,
                step_number,
                requesting_agent,
                &context.capabilities,
                reason.clone(),
            )?;
            return Err(AuthorizationError::AgentIdentityMismatch {
                recorded: context.agent_id,
                requested: requesting_agent.to_string(),
            });
        }

        // 5. Policy drift is reported, never assumed away.
        let drift = self
            .policy
            .drift_since(&context.policy_id, context.policy_version);

        // 5b. The runtime — not the agent — decides how much authority the
        //     pending operation needs.  The recorded intent is narrowed to the
        //     capability family the tool manifest declares for this operation.
        let required_kind = match context.required_capability {
            Some(kind) => kind,
            None => {
                let reason = format!(
                    "capability requirements for '{}/{}' could not be derived from the tool \
                     manifest; refusing to re-authorize an operation of unknown authority",
                    checkpoint.tool_id.as_deref().unwrap_or("?"),
                    checkpoint.operation_id.as_deref().unwrap_or("?")
                );
                self.record_denial(
                    task_id,
                    step_number,
                    requesting_agent,
                    &context.capabilities,
                    reason.clone(),
                )?;
                self.fail_task_for_revoked_grant(task_id, step_number, &reason)?;
                return Err(AuthorizationError::CapabilityRequirementsUnderivable {
                    task_id,
                    step_number,
                    tool_id: checkpoint.tool_id.clone().unwrap_or_default(),
                    operation_id: checkpoint.operation_id.clone().unwrap_or_default(),
                });
            }
        };

        let scoped_capabilities: Vec<Capability> = context
            .capabilities
            .iter()
            .filter(|capability| CapabilityKind::of(capability) == required_kind)
            .cloned()
            .collect();

        if scoped_capabilities.is_empty() {
            let reason = format!(
                "the recorded capability intent does not cover the pending operation: it \
                 requires {required_kind}, but the intent grants only {:?}",
                context.capabilities
            );
            self.record_denial(
                task_id,
                step_number,
                requesting_agent,
                &context.capabilities,
                reason.clone(),
            )?;
            self.fail_task_for_revoked_grant(task_id, step_number, &reason)?;
            return Err(AuthorizationError::IntentDoesNotCoverOperation {
                task_id,
                step_number,
                required: required_kind,
            });
        }

        // 6. Re-evaluate the *narrowed* set against the policy in force *now*.
        let engine = PolicyEngine::new(Some(self.event_bus));
        let outcome = engine
            .authorize_capability_set(self.policy, requesting_agent, task_id, &scoped_capabilities)
            .map_err(|error| AuthorizationError::AuditFailure(error.to_string()))?;

        if !outcome.is_granted() {
            let reason = match &outcome {
                crate::permissions::policy::AuthorizationOutcome::Denied { reason, .. } => {
                    reason.clone()
                }
                crate::permissions::policy::AuthorizationOutcome::Granted { .. } => unreachable!(),
            };
            self.record_denial(
                task_id,
                step_number,
                requesting_agent,
                &scoped_capabilities,
                reason.clone(),
            )?;
            self.fail_task_for_revoked_grant(task_id, step_number, &reason)?;
            return Err(AuthorizationError::Refused {
                task_id,
                step_number,
                reason,
            });
        }

        // 7. Mint a short-lived grant bounded by exactly the derived scope.
        let grant = self.grant_issuer.issue_grant(
            requesting_agent,
            task_id,
            scoped_capabilities.clone(),
            Some(Duration::seconds(RECOVERY_GRANT_TTL_SECONDS)),
        );

        // 8. The decision must be durable before the grant may be used.  If it
        //    cannot be recorded, the freshly minted grant is revoked again.
        let decided_at = Utc::now();
        let decision = AuthorizationDecisionRecord {
            decision_id: Uuid::new_v4(),
            task_id,
            step_number,
            agent_id: requesting_agent.to_string(),
            granted: true,
            reason: format!(
                "policy {} v{} authorizes the runtime-derived {required_kind} requirement",
                self.policy.policy_id(),
                self.policy.version()
            ),
            grant_id: Some(grant.grant_id),
            requested_capabilities: scoped_capabilities.clone(),
            policy_id: self.policy.policy_id().to_string(),
            policy_version: self.policy.version(),
            decided_at: decided_at.to_rfc3339(),
        };

        if let Err(error) = self.authorization_store.record_decision(&decision) {
            let _ = self.grant_issuer.revoke_grant(&grant.grant_id);
            return Err(AuthorizationError::AuditFailure(error.to_string()));
        }

        if let Err(error) = self.event_bus.emit_event(
            Some(&task_id.to_string()),
            EVENT_REAUTHORIZATION_GRANTED,
            serde_json::json!({
                "task_id": task_id,
                "step_number": step_number,
                "agent_id": requesting_agent,
                "grant_id": grant.grant_id,
                "capabilities": scoped_capabilities,
                "required_capability": required_kind.as_str(),
                "recorded_intent": context.capabilities,
                "policy_id": self.policy.policy_id(),
                "policy_version": self.policy.version(),
                "policy_drift": drift.as_str(),
                "recorded_policy_id": context.policy_id,
                "recorded_policy_version": context.policy_version,
                "expires_at": grant.expires_at,
            }),
        ) {
            let _ = self.grant_issuer.revoke_grant(&grant.grant_id);
            return Err(AuthorizationError::AuditFailure(error.to_string()));
        }

        Ok(RecoveryAuthorization {
            task_id,
            step_number,
            agent_id: requesting_agent.to_string(),
            grant,
            capabilities: scoped_capabilities,
            policy_id: self.policy.policy_id().to_string(),
            policy_version: self.policy.version(),
            policy_drift: drift,
            decided_at,
        })
    }

    fn load_retry_eligible_checkpoint(
        &self,
        task_id: Uuid,
        step_number: usize,
    ) -> Result<TaskCheckpoint, AuthorizationError> {
        let checkpoint = self.checkpoint_store.get(task_id, step_number)?.ok_or(
            AuthorizationError::CheckpointNotFound {
                task_id,
                step_number,
            },
        )?;

        if checkpoint.status != CheckpointStatus::RetryReady {
            return Err(AuthorizationError::NotRetryEligible {
                task_id,
                step_number,
                status: checkpoint.status.as_str().to_string(),
            });
        }

        if checkpoint.invocation_id.is_none()
            || checkpoint.idempotency_key.is_none()
            || checkpoint.argument_fingerprint.is_none()
        {
            return Err(AuthorizationError::IncompleteCheckpoint {
                task_id,
                step_number,
            });
        }

        Ok(checkpoint)
    }

    fn record_denial(
        &self,
        task_id: Uuid,
        step_number: usize,
        agent_id: &str,
        capabilities: &[Capability],
        reason: String,
    ) -> Result<(), AuthorizationError> {
        let decided_at = Utc::now();
        let decision = AuthorizationDecisionRecord {
            decision_id: Uuid::new_v4(),
            task_id,
            step_number,
            agent_id: agent_id.to_string(),
            granted: false,
            reason: reason.clone(),
            grant_id: None,
            requested_capabilities: capabilities.to_vec(),
            policy_id: self.policy.policy_id().to_string(),
            policy_version: self.policy.version(),
            decided_at: decided_at.to_rfc3339(),
        };

        self.authorization_store.record_decision(&decision)?;

        self.event_bus.emit_event(
            Some(&task_id.to_string()),
            EVENT_REAUTHORIZATION_DENIED,
            serde_json::json!({
                "task_id": task_id,
                "step_number": step_number,
                "agent_id": agent_id,
                "reason": reason,
                "policy_id": self.policy.policy_id(),
                "policy_version": self.policy.version(),
            }),
        )?;

        Ok(())
    }

    /// Failing the task is the last line of defence: even if the caller ignores
    /// the error, the task can no longer be picked up as `Running`.
    fn fail_task_for_revoked_grant(
        &self,
        task_id: Uuid,
        _step_number: usize,
        reason: &str,
    ) -> Result<(), AuthorizationError> {
        let Some(task) = self.task_store.get_task(&task_id)? else {
            return Ok(());
        };

        if task.state != TaskState::Running {
            return Ok(());
        }

        self.task_store
            .transition_state(task_id, TaskState::Running, TaskState::Failed)?;
        self.event_bus.emit_event(
            Some(&task_id.to_string()),
            "TaskFailedGrantRevokedOnRecovery",
            serde_json::json!({
                "task_id": task_id,
                "reason": reason,
                "policy_id": self.policy.policy_id(),
                "policy_version": self.policy.version(),
            }),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("skyos-authz-{tag}-{unique}"))
    }

    fn issue_context(store: &AuthorizationStore, task_id: Uuid) {
        let conn = store.connection().unwrap();
        AuthorizationStore::record_with_connection(
            &conn,
            &AuthorizationContext {
                task_id,
                step_number: 0,
                agent_id: "agent-a".into(),
                capabilities: vec![Capability::FileSystemRead {
                    root: std::path::PathBuf::from("/repo"),
                }],
                required_capability: Some(CapabilityKind::FileSystemRead),
                policy_id: "policy".into(),
                policy_version: 1,
                recorded_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }

    #[test]
    fn authorization_context_round_trips() {
        let dir = temp_dir("ctx");
        let path = dir.join("runtime_state.db");
        let store = AuthorizationStore::open(&path).unwrap();
        let task_id = Uuid::new_v4();

        issue_context(&store, task_id);
        let loaded = store.get(task_id, 0).unwrap().unwrap();
        assert_eq!(loaded.agent_id, "agent-a");
        assert_eq!(loaded.policy_version, 1);
        assert_eq!(loaded.capabilities.len(), 1);

        assert!(store.get(task_id, 1).unwrap().is_none());

        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn denial_decisions_are_append_only() {
        let dir = temp_dir("decisions");
        let path = dir.join("runtime_state.db");
        let store = AuthorizationStore::open(&path).unwrap();
        let task_id = Uuid::new_v4();

        for (granted, reason) in [(false, "revoked"), (true, "ok")] {
            store
                .record_decision(&AuthorizationDecisionRecord {
                    decision_id: Uuid::new_v4(),
                    task_id,
                    step_number: 0,
                    agent_id: "agent-a".into(),
                    granted,
                    reason: reason.into(),
                    grant_id: None,
                    requested_capabilities: vec![],
                    policy_id: "policy".into(),
                    policy_version: 1,
                    decided_at: Utc::now().to_rfc3339(),
                })
                .unwrap();
        }

        let decisions = store.list_decisions(task_id).unwrap();
        assert_eq!(decisions.len(), 2);
        assert!(decisions.iter().any(|decision| decision.granted));
        assert!(decisions.iter().any(|decision| !decision.granted));

        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
