/// Phase 5.4 — Durable reconciliation and re-queue audit.
///
/// A checkpoint describes what the runtime knows.  Reconciliation is the
/// separate, attributable act that changes what the runtime is willing to
/// assume.  This module stores those acts: who decided, why, on what evidence,
/// and what the checkpoint state was before and after.
///
/// The checkpoint row itself is never deleted and its identity columns
/// (`invocation_id`, `idempotency_key`, `argument_fingerprint`) are never
/// rewritten by reconciliation.  Only its status advances, and the prior status
/// is preserved here so the crash history remains legible.
use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;
use uuid::Uuid;

use crate::persistence::db::{DatabaseConnectionPool, DatabaseError};

#[derive(Debug, Error)]
pub enum ReconciliationError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("unknown reconciliation action: '{0}'")]
    InvalidAction(String),
    #[error("UUID parse error: {0}")]
    UuidParse(#[from] uuid::Error),
}

/// What an actor decided to do about an uncertain step or a blocked task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationAction {
    /// Physical evidence proved the effect happened; adopt it without
    /// re-executing anything.
    AdoptExistingArtifact,
    /// Physical evidence proved the effect did not happen; the step may be
    /// retried under a fresh authorization.
    AuthorizeRetry,
    /// Evidence was insufficient; nothing changes.
    Indeterminate,
    /// An operator put a blocked task back in the queue after its uncertainty
    /// was resolved.
    RequeueForExecution,
}

impl ReconciliationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AdoptExistingArtifact => "AdoptExistingArtifact",
            Self::AuthorizeRetry => "AuthorizeRetry",
            Self::Indeterminate => "Indeterminate",
            Self::RequeueForExecution => "RequeueForExecution",
        }
    }
}

impl TryFrom<&str> for ReconciliationAction {
    type Error = ReconciliationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "AdoptExistingArtifact" => Ok(Self::AdoptExistingArtifact),
            "AuthorizeRetry" => Ok(Self::AuthorizeRetry),
            "Indeterminate" => Ok(Self::Indeterminate),
            "RequeueForExecution" => Ok(Self::RequeueForExecution),
            other => Err(ReconciliationError::InvalidAction(other.to_string())),
        }
    }
}

/// One attributed reconciliation decision.
///
/// Phase 6.0 added provenance: the actor's verified kind and authentication
/// method, the grant that authorized the action, the invocation it resolved,
/// and the raw observation the verdict was derived from. A legacy row (all
/// `None`/empty) must never be read as independently verified.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconciliationRecord {
    pub reconciliation_id: Uuid,
    pub task_id: Uuid,
    pub step_number: usize,
    pub actor_id: String,
    pub action: ReconciliationAction,
    pub reason: String,
    pub evidence: String,
    pub prior_status: String,
    pub new_status: String,
    pub created_at: String,
    pub invocation_id: Option<Uuid>,
    pub verdict: String,
    pub evidence_kind: String,
    pub evidence_source: String,
    pub evidence_json: String,
    pub actor_kind: String,
    pub auth_method: String,
    pub grant_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct ReconciliationStore {
    pool: DatabaseConnectionPool,
}

impl ReconciliationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReconciliationError> {
        let pool = DatabaseConnectionPool::open(path)?;
        let conn = pool.connection()?;
        crate::persistence::migrations::apply_recovery_schema(&conn)?;
        Ok(Self { pool })
    }

    pub fn connection(&self) -> Result<Connection, ReconciliationError> {
        Ok(self.pool.connection()?)
    }

    pub fn record_with_connection(
        conn: &Connection,
        record: &ReconciliationRecord,
    ) -> Result<(), ReconciliationError> {
        conn.execute(
            "INSERT INTO task_reconciliations \
             (reconciliation_id, task_id, step_number, actor_id, action, reason, evidence, \
              prior_status, new_status, created_at, invocation_id, verdict, evidence_kind, \
              evidence_source, evidence_json, actor_kind, auth_method, grant_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                     ?17, ?18)",
            rusqlite::params![
                record.reconciliation_id.to_string(),
                record.task_id.to_string(),
                record.step_number as i64,
                &record.actor_id,
                record.action.as_str(),
                &record.reason,
                &record.evidence,
                &record.prior_status,
                &record.new_status,
                &record.created_at,
                record.invocation_id.map(|id| id.to_string()),
                &record.verdict,
                &record.evidence_kind,
                &record.evidence_source,
                &record.evidence_json,
                &record.actor_kind,
                &record.auth_method,
                record.grant_id.map(|id| id.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn record(&self, record: &ReconciliationRecord) -> Result<(), ReconciliationError> {
        let conn = self.pool.connection()?;
        Self::record_with_connection(&conn, record)
    }

    /// Every reconciliation decision for `task_id`, oldest first.
    pub fn list_for_task(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<ReconciliationRecord>, ReconciliationError> {
        let conn = self.pool.connection()?;
        let mut stmt = conn.prepare(
            "SELECT reconciliation_id, task_id, step_number, actor_id, action, reason, \
                    evidence, prior_status, new_status, created_at, invocation_id, verdict, \
                    evidence_kind, evidence_source, evidence_json, actor_kind, auth_method, \
                    grant_id \
             FROM task_reconciliations WHERE task_id = ?1 \
             ORDER BY created_at ASC, rowid ASC",
        )?;
        let rows = stmt.query_map([task_id.to_string()], |row| {
            Ok((
                row.get::<_, String>("reconciliation_id")?,
                row.get::<_, i64>("step_number")?,
                row.get::<_, String>("actor_id")?,
                row.get::<_, String>("action")?,
                row.get::<_, String>("reason")?,
                row.get::<_, String>("evidence")?,
                row.get::<_, String>("prior_status")?,
                row.get::<_, String>("new_status")?,
                row.get::<_, String>("created_at")?,
                row.get::<_, Option<String>>("invocation_id")?,
                row.get::<_, Option<String>>("verdict")?,
                row.get::<_, Option<String>>("evidence_kind")?,
                row.get::<_, Option<String>>("evidence_source")?,
                row.get::<_, Option<String>>("evidence_json")?,
                row.get::<_, Option<String>>("actor_kind")?,
                row.get::<_, Option<String>>("auth_method")?,
                row.get::<_, Option<String>>("grant_id")?,
            ))
        })?;

        let mut records = Vec::new();
        for row in rows {
            let (
                reconciliation_id,
                step,
                actor_id,
                action,
                reason,
                evidence,
                prior_status,
                new_status,
                created_at,
                invocation_id,
                verdict,
                evidence_kind,
                evidence_source,
                evidence_json,
                actor_kind,
                auth_method,
                grant_id,
            ) = row?;
            records.push(ReconciliationRecord {
                reconciliation_id: Uuid::parse_str(&reconciliation_id)?,
                task_id,
                step_number: step as usize,
                actor_id,
                action: ReconciliationAction::try_from(action.as_str())?,
                reason,
                evidence,
                prior_status,
                new_status,
                created_at,
                invocation_id: invocation_id.map(|id| Uuid::parse_str(&id)).transpose()?,
                verdict: verdict.unwrap_or_default(),
                evidence_kind: evidence_kind.unwrap_or_default(),
                evidence_source: evidence_source.unwrap_or_default(),
                evidence_json: evidence_json.unwrap_or_default(),
                actor_kind: actor_kind.unwrap_or_default(),
                auth_method: auth_method.unwrap_or_default(),
                grant_id: grant_id.map(|id| Uuid::parse_str(&id)).transpose()?,
            });
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_in_order() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-reconcile-{unique}"));
        let path = dir.join("runtime_state.db");
        let store = ReconciliationStore::open(&path).unwrap();
        let task_id = Uuid::new_v4();

        for action in [
            ReconciliationAction::AdoptExistingArtifact,
            ReconciliationAction::RequeueForExecution,
        ] {
            store
                .record(&ReconciliationRecord {
                    reconciliation_id: Uuid::new_v4(),
                    task_id,
                    step_number: 0,
                    actor_id: "operator-1".into(),
                    action,
                    reason: "verified".into(),
                    evidence: "commit present".into(),
                    prior_status: "OutcomeUnknown".into(),
                    new_status: "Succeeded".into(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    invocation_id: Some(Uuid::new_v4()),
                    verdict: "ConfirmedSucceeded".into(),
                    evidence_kind: "GitCommit".into(),
                    evidence_source: "git log".into(),
                    evidence_json: "{\"matching_commits\":1}".into(),
                    actor_kind: "Operator".into(),
                    auth_method: "LocalProcess".into(),
                    grant_id: Some(Uuid::new_v4()),
                })
                .unwrap();
        }

        let records = store.list_for_task(task_id).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].action,
            ReconciliationAction::AdoptExistingArtifact
        );
        assert_eq!(records[0].actor_id, "operator-1");

        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
