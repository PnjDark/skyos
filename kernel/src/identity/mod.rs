//! Phase 6.0 — Authenticated actor identity.
//!
//! The Phase 5 reconciliation audit recorded an `actor_id` that the caller
//! supplied. That is attribution without authentication: any caller could claim
//! to be anyone.
//!
//! This module makes the claim/verification split explicit:
//!
//! * A caller presents an [`ActorClaim`] — plain data, carrying no authority.
//! * The runtime runs its configured [`ActorAuthenticator`] over the claim.
//! * Only the runtime can turn a [`VerifiedIdentity`] into an
//!   [`AuthenticatedActor`], because [`AuthenticatedActor::from_verified`] is
//!   crate-private and the struct has no public constructor.
//!
//! A host crate cannot mint an actor even if it wants to: the type is
//! unconstructible outside this crate. What a host *can* do is supply the
//! authenticator, which is the trust anchor — it already owns the process.
use serde::{Deserialize, Serialize};
use thiserror::Error;

use chrono::{DateTime, Utc};

/// What kind of principal is acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorKind {
    /// A human operator acting through a host tool.
    Operator,
    /// The runtime itself (automatic maintenance, failure handling).
    Runtime,
    /// An agent executing a task. Never permitted to reconcile.
    Agent,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "Operator",
            Self::Runtime => "Runtime",
            Self::Agent => "Agent",
        }
    }
}

impl std::fmt::Display for ActorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an identity was established. Recorded verbatim in the audit trail so the
/// ledger never implies a stronger guarantee than the one that was applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// OS-level process token (uid / SID). The strongest local method.
    LocalProcess { platform_id: String },
    /// Environment-derived user and host. Attributable, not verified.
    EnvironmentClaimed { os_user: String, host: String },
    /// A configured or externally verified bearer token.
    SignedToken { key_id: String },
    /// Test composition only; never produced by a production authenticator.
    HarnessOnly,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalProcess { .. } => "LocalProcess",
            Self::EnvironmentClaimed { .. } => "EnvironmentClaimed",
            Self::SignedToken { .. } => "SignedToken",
            Self::HarnessOnly => "HarnessOnly",
        }
    }

    /// True when the identity was verified against a platform or cryptographic
    /// authority rather than asserted by the caller.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::LocalProcess { .. } | Self::SignedToken { .. })
    }
}

/// The evidence a caller presents alongside its claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// No credential; the host may still authenticate from process context.
    None,
    /// "Use whatever this process is"; resolved by the authenticator.
    ProcessContext,
    /// An opaque bearer token, verified by the authenticator.
    Token(String),
}

/// What a caller says it is. Deliberately forgeable — it carries no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorClaim {
    pub claimed_id: String,
    pub kind: ActorKind,
    pub credential: Credential,
}

impl ActorClaim {
    /// "Authenticate whoever is running this process."
    pub fn process(kind: ActorKind) -> Self {
        Self {
            claimed_id: String::new(),
            kind,
            credential: Credential::ProcessContext,
        }
    }

    /// Claim a specific operator identity, to be verified by the authenticator.
    pub fn operator(claimed_id: impl Into<String>) -> Self {
        Self {
            claimed_id: claimed_id.into(),
            kind: ActorKind::Operator,
            credential: Credential::None,
        }
    }

    pub fn agent(claimed_id: impl Into<String>) -> Self {
        Self {
            claimed_id: claimed_id.into(),
            kind: ActorKind::Agent,
            credential: Credential::None,
        }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.credential = Credential::Token(token.into());
        self
    }
}

/// The authenticator's verdict. Plain data, and it never crosses the API
/// boundary: the engine consumes it immediately and constructs the actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub id: String,
    pub kind: ActorKind,
    pub method: AuthMethod,
    pub verified_at: DateTime<Utc>,
}

impl VerifiedIdentity {
    pub fn new(id: impl Into<String>, kind: ActorKind, method: AuthMethod) -> Self {
        Self {
            id: id.into(),
            kind,
            method,
            verified_at: Utc::now(),
        }
    }
}

/// Authority-bearing identity.
///
/// No public constructor, no `From<String>`, no `Default`. Outside this crate
/// the only way to obtain one is to call an entry point that authenticates a
/// claim itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedActor {
    id: String,
    kind: ActorKind,
    method: AuthMethod,
    authenticated_at: DateTime<Utc>,
}

impl AuthenticatedActor {
    /// Crate-private: only the runtime's authenticated entry points call this.
    pub(crate) fn from_verified(verified: VerifiedIdentity) -> Self {
        Self {
            id: verified.id,
            kind: verified.kind,
            method: verified.method,
            authenticated_at: verified.verified_at,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> ActorKind {
        self.kind
    }

    pub fn method(&self) -> &AuthMethod {
        &self.method
    }

    pub fn authenticated_at(&self) -> DateTime<Utc> {
        self.authenticated_at
    }
}

/// Maps a claim to a verified identity, or refuses.
///
/// Implementations live in the host crate (the process owner), keeping the
/// kernel free of platform dependencies.
pub trait ActorAuthenticator: Send + Sync {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError>;
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("this authenticator cannot verify actor kind {kind}: {reason}")]
    UnsupportedActorKind { kind: ActorKind, reason: String },
    #[error("missing or unsupported credential: {0}")]
    UnsupportedCredential(String),
    #[error("identity verification failed: {0}")]
    VerificationFailed(String),
    #[error("claimed identity '{claimed}' does not match the verified identity '{actual}'")]
    IdentityMismatch { claimed: String, actual: String },
}

/// An authenticator that refuses everything. The safe default for a runtime
/// that has not been configured with a real trust anchor.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllAuthenticator;

impl ActorAuthenticator for DenyAllAuthenticator {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
        Err(AuthError::VerificationFailed(format!(
            "no authenticator configured; refusing claim for '{}'",
            claim.claimed_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedAuthenticator;

    impl ActorAuthenticator for FixedAuthenticator {
        fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
            if claim.kind == ActorKind::Agent {
                return Err(AuthError::UnsupportedActorKind {
                    kind: ActorKind::Agent,
                    reason: "agents hold no operator credential".into(),
                });
            }
            Ok(VerifiedIdentity::new(
                "operator-1",
                ActorKind::Operator,
                AuthMethod::LocalProcess {
                    platform_id: "test".into(),
                },
            ))
        }
    }

    #[test]
    fn verified_identity_carries_the_authenticator_verdict() {
        let actor = FixedAuthenticator
            .verify(&ActorClaim::process(ActorKind::Operator))
            .map(AuthenticatedActor::from_verified)
            .unwrap();

        assert_eq!(actor.id(), "operator-1");
        assert_eq!(actor.kind(), ActorKind::Operator);
        assert_eq!(actor.method().as_str(), "LocalProcess");
        assert!(actor.method().is_verified());
    }

    #[test]
    fn an_authenticator_can_refuse_agents() {
        let error = FixedAuthenticator
            .verify(&ActorClaim::agent("agent-7"))
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::UnsupportedActorKind {
                kind: ActorKind::Agent,
                ..
            }
        ));
    }

    #[test]
    fn deny_all_never_verifies() {
        assert!(
            DenyAllAuthenticator
                .verify(&ActorClaim::operator("someone"))
                .is_err()
        );
    }

    #[test]
    fn environment_claimed_identity_is_not_reported_as_verified() {
        let method = AuthMethod::EnvironmentClaimed {
            os_user: "penjy".into(),
            host: "workstation".into(),
        };
        assert!(!method.is_verified());
    }
}
