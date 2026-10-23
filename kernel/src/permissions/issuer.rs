use crate::permissions::types::{Capability, CapabilityGrant};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum IssuerError {
    #[error("Grant {0} not found")]
    GrantNotFound(Uuid),
    #[error("Grant {0} is already revoked")]
    AlreadyRevoked(Uuid),
}

/// Kernel-owned authority for minting and revoking capability grants.
#[derive(Clone, Default)]
pub struct GrantIssuer {
    grants: Arc<Mutex<HashMap<Uuid, CapabilityGrant>>>,
}

impl GrantIssuer {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Issue a short-lived capability grant (default 15 minutes unless specified).
    pub fn issue_grant(
        &self,
        agent_id: impl Into<String>,
        task_id: Uuid,
        capabilities: Vec<Capability>,
        ttl: Option<Duration>,
    ) -> CapabilityGrant {
        let now = Utc::now();
        let duration = ttl.unwrap_or_else(|| Duration::minutes(15));
        let grant = CapabilityGrant {
            grant_id: Uuid::new_v4(),
            agent_id: agent_id.into(),
            task_id,
            capabilities,
            issued_at: now,
            expires_at: now + duration,
            revoked: false,
        };
        let mut lock = self.grants.lock().expect("GrantIssuer mutex poisoned");
        lock.insert(grant.grant_id, grant.clone());
        grant
    }

    /// Get active grant by ID.
    pub fn get_grant(&self, grant_id: &Uuid) -> Option<CapabilityGrant> {
        let lock = self.grants.lock().expect("GrantIssuer mutex poisoned");
        lock.get(grant_id).cloned()
    }

    /// Get active (valid, unexpired, unrevoked) grant for a task.
    pub fn get_active_grant_for_task(&self, task_id: &Uuid) -> Option<CapabilityGrant> {
        let lock = self.grants.lock().expect("GrantIssuer mutex poisoned");
        lock.values()
            .find(|g| g.task_id == *task_id && g.is_valid())
            .cloned()
    }

    /// Immediately revoke an active grant.
    pub fn revoke_grant(&self, grant_id: &Uuid) -> Result<(), IssuerError> {
        let mut lock = self.grants.lock().expect("GrantIssuer mutex poisoned");
        if let Some(grant) = lock.get_mut(grant_id) {
            if grant.revoked {
                return Err(IssuerError::AlreadyRevoked(*grant_id));
            }
            grant.revoked = true;
            Ok(())
        } else {
            Err(IssuerError::GrantNotFound(*grant_id))
        }
    }
}
