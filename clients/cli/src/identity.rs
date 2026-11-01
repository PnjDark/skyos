//! Host-side actor authentication for the `sky` operator.
//!
//! Two authenticators live here, with deliberately different strengths:
//!
//! * [`LocalProcessAuthenticator`] reads the OS process identity — the Windows
//!   token SID or the Unix uid — and reports `AuthMethod::LocalProcess`, which
//!   [`AuthMethod::is_verified`] treats as verified. This is the default.
//! * [`HostOperatorAuthenticator`] falls back to environment variables and
//!   reports `AuthMethod::EnvironmentClaimed`, which is *not* verified. It
//!   exists for environments where the platform call fails, and says so in the
//!   audit trail rather than pretending otherwise.
//!
//! The kernel owns the type barrier: `AuthenticatedActor` cannot be constructed
//! outside `kernel`, so a host can supply an authenticator but can never hand
//! the engine a pre-blessed actor.
use std::env;

use kernel::identity::{
    ActorAuthenticator, ActorClaim, ActorKind, AuthError, AuthMethod, Credential, VerifiedIdentity,
};

// ── Platform identity ────────────────────────────────────────────────────────

/// The OS process identity, prefixed so the audit trail shows its provenance.
#[cfg(windows)]
fn process_identity() -> Option<String> {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }

        // First call sizes the buffer; the second fills it.
        let mut length: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
        if length == 0 {
            let _ = CloseHandle(token);
            return None;
        }

        // u64 storage guarantees the alignment `TOKEN_USER` requires; a Vec<u8>
        // would only guarantee alignment 1.
        let words = (length as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buffer: Vec<u64> = vec![0; words];
        let filled = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            length,
            &mut length,
        );
        let _ = CloseHandle(token);
        if filled == 0 {
            return None;
        }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_string: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) == 0 {
            return None;
        }

        let mut len = 0usize;
        while *sid_string.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len));
        LocalFree(sid_string as HLOCAL);

        Some(format!("win-sid:{sid}"))
    }
}

#[cfg(unix)]
fn process_identity() -> Option<String> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    Some(format!("unix-uid:{uid}"))
}

#[cfg(not(any(windows, unix)))]
fn process_identity() -> Option<String> {
    None
}

fn environment_identity() -> Option<(String, String)> {
    let user = env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let host = env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    Some((user, host))
}

fn refuse_agents(claim: &ActorClaim) -> Result<(), AuthError> {
    if claim.kind == ActorKind::Agent {
        return Err(AuthError::UnsupportedActorKind {
            kind: ActorKind::Agent,
            reason: "an agent is never an operator, whatever it claims".to_string(),
        });
    }
    Ok(())
}

fn check_claimed_id(claim: &ActorClaim, actual: &str) -> Result<(), AuthError> {
    if claim.claimed_id.is_empty() || claim.claimed_id == actual {
        Ok(())
    } else {
        Err(AuthError::IdentityMismatch {
            claimed: claim.claimed_id.clone(),
            actual: actual.to_string(),
        })
    }
}

// ── Verified process identity ────────────────────────────────────────────────

/// Authenticates the operating-system process running this binary.
///
/// This is the strongest local claim available: on Windows it reads the token
/// SID, on Unix the effective uid. It never falls back silently — if the
/// platform call fails, verification fails.
#[derive(Debug, Clone, Default)]
pub struct LocalProcessAuthenticator;

impl LocalProcessAuthenticator {
    pub fn new() -> Self {
        Self
    }
}

impl ActorAuthenticator for LocalProcessAuthenticator {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
        refuse_agents(claim)?;

        if !matches!(
            claim.credential,
            Credential::None | Credential::ProcessContext
        ) {
            return Err(AuthError::UnsupportedCredential(
                "LocalProcessAuthenticator accepts process context, not bearer tokens".to_string(),
            ));
        }

        let platform_id = process_identity().ok_or_else(|| {
            AuthError::VerificationFailed(
                "could not read the OS process identity; refusing to fall back to the \
                 environment"
                    .to_string(),
            )
        })?;

        check_claimed_id(claim, &platform_id)?;

        Ok(VerifiedIdentity::new(
            platform_id.clone(),
            ActorKind::Operator,
            AuthMethod::LocalProcess { platform_id },
        ))
    }
}

// ── Environment fallback ─────────────────────────────────────────────────────

/// Attributable but unverified: binds the actor to the local user and host from
/// the environment. Recorded as `EnvironmentClaimed`, never as `LocalProcess`.
#[derive(Debug, Clone, Default)]
pub struct HostOperatorAuthenticator;

impl HostOperatorAuthenticator {
    pub fn new() -> Self {
        Self
    }
}

impl ActorAuthenticator for HostOperatorAuthenticator {
    fn verify(&self, claim: &ActorClaim) -> Result<VerifiedIdentity, AuthError> {
        refuse_agents(claim)?;

        let (os_user, host) = environment_identity().ok_or_else(|| {
            AuthError::VerificationFailed(
                "no OS user is defined in this environment; refusing to authenticate".to_string(),
            )
        })?;

        check_claimed_id(claim, &os_user)?;

        Ok(VerifiedIdentity::new(
            os_user.clone(),
            ActorKind::Operator,
            AuthMethod::EnvironmentClaimed { os_user, host },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_authenticators_refuse_agent_claims() {
        for error in [
            LocalProcessAuthenticator
                .verify(&ActorClaim::agent("agent-1"))
                .unwrap_err(),
            HostOperatorAuthenticator
                .verify(&ActorClaim::agent("agent-1"))
                .unwrap_err(),
        ] {
            assert!(matches!(error, AuthError::UnsupportedActorKind { .. }));
        }
    }

    #[test]
    fn local_process_identity_is_reported_as_verified() {
        let authenticator = LocalProcessAuthenticator;
        match authenticator.verify(&ActorClaim::process(ActorKind::Operator)) {
            Ok(verified) => {
                assert!(
                    verified.method.is_verified(),
                    "a process token identity must be marked verified"
                );
                assert!(matches!(verified.method, AuthMethod::LocalProcess { .. }));
                assert!(!verified.id.is_empty());
                assert!(
                    verified.id.starts_with("win-sid:") || verified.id.starts_with("unix-uid:"),
                    "unexpected identity shape: {}",
                    verified.id
                );
            }
            Err(AuthError::VerificationFailed(reason)) => {
                // Only acceptable on a platform without a supported identity
                // source; must be a refusal, not a silent downgrade.
                assert!(reason.contains("refusing to fall back"));
            }
            Err(other) => panic!("unexpected authentication error: {other}"),
        }
    }

    #[test]
    fn environment_identity_is_not_reported_as_verified() {
        let Ok(verified) =
            HostOperatorAuthenticator.verify(&ActorClaim::process(ActorKind::Operator))
        else {
            return; // no OS user in this environment
        };
        assert!(!verified.method.is_verified());
        assert!(matches!(
            verified.method,
            AuthMethod::EnvironmentClaimed { .. }
        ));
    }

    #[test]
    fn a_claimed_identity_must_match_the_process_identity() {
        let Some(expected) = process_identity() else {
            return;
        };
        let error = LocalProcessAuthenticator
            .verify(&ActorClaim::operator("somebody-else"))
            .unwrap_err();
        assert!(matches!(error, AuthError::IdentityMismatch { .. }));

        // The true identity is accepted.
        assert!(LocalProcessAuthenticator
            .verify(&ActorClaim::operator(expected))
            .is_ok());
    }

    #[test]
    fn local_process_authenticator_refuses_bearer_tokens() {
        let error = LocalProcessAuthenticator
            .verify(&ActorClaim::process(ActorKind::Operator).with_token("abc"))
            .unwrap_err();
        assert!(matches!(error, AuthError::UnsupportedCredential(_)));
    }
}
