use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::permissions::types::Capability;

pub struct PolicyValidator;

impl PolicyValidator {
    /// Validates a filesystem request against a root capability using path normalization & lexical containment checks.
    pub fn validate_fs_access(requested_path: &std::path::Path, root: &std::path::Path) -> bool {
        let normalized_requested = Self::normalize_path(requested_path);
        let normalized_root = Self::normalize_path(root);
        normalized_requested.starts_with(&normalized_root)
    }

    /// Validates a process execution request against a capability.
    /// Ensures the program matches exactly, arguments start with allowed prefixes, and workdir is within allowed workdir.
    pub fn validate_process_exec(
        program: &str,
        args: &[String],
        workdir: &std::path::Path,
        allowed_program: &str,
        allowed_args_prefix: &[String],
        allowed_workdir: &std::path::Path,
    ) -> bool {
        if program != allowed_program {
            return false;
        }
        // Check each argument matches exactly the allowed prefix sequence
        if args.len() < allowed_args_prefix.len() {
            return false;
        }
        for (arg, allowed) in args.iter().zip(allowed_args_prefix.iter()) {
            if arg != allowed {
                return false;
            }
        }
        // Workdir must be within allowed_workdir after normalization
        Self::validate_fs_access(workdir, allowed_workdir)
    }

    /// Lexically normalizes a path without requiring it to exist on disk (resolving . and .. components).
    pub fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
        use std::path::Component;
        let mut components: Vec<std::ffi::OsString> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    components.clear();
                    components.push(component.as_os_str().to_owned());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    components.pop();
                }
                Component::Normal(c) => {
                    components.push(c.to_owned());
                }
            }
        }
        components.iter().collect()
    }

    /// True when `granted` is at least as permissive as `requested`.
    ///
    /// This is *scope subsumption*: a policy rule that authorizes
    /// `FileSystemWrite{root: "/repo"}` covers a request for
    /// `FileSystemWrite{root: "/repo/src"}`, but never the reverse.
    pub fn capability_covers(granted: &Capability, requested: &Capability) -> bool {
        match (granted, requested) {
            (
                Capability::FileSystemRead { root: granted_root },
                Capability::FileSystemRead {
                    root: requested_root,
                },
            )
            | (
                Capability::FileSystemWrite { root: granted_root },
                Capability::FileSystemWrite {
                    root: requested_root,
                },
            ) => Self::validate_fs_access(requested_root, granted_root),

            (
                Capability::ProcessExec {
                    program: granted_program,
                    allowed_args_prefix: granted_args,
                    allowed_workdir: granted_workdir,
                },
                Capability::ProcessExec {
                    program: requested_program,
                    allowed_args_prefix: requested_args,
                    allowed_workdir: requested_workdir,
                },
            ) => {
                // The granted prefix must itself be a prefix of the requested
                // one: a narrower request can never widen what the rule allows.
                granted_program == requested_program
                    && requested_args.len() >= granted_args.len()
                    && granted_args
                        .iter()
                        .zip(requested_args.iter())
                        .all(|(granted, requested)| granted == requested)
                    && Self::validate_fs_access(requested_workdir, granted_workdir)
            }

            (
                Capability::NetworkOutbound {
                    allowed_domain: granted_domain,
                },
                Capability::NetworkOutbound {
                    allowed_domain: requested_domain,
                },
            ) => granted_domain == "*" || granted_domain == requested_domain,

            (
                Capability::ContainersExec {
                    container_pattern: granted_pattern,
                },
                Capability::ContainersExec {
                    container_pattern: requested_pattern,
                },
            ) => granted_pattern == "*" || granted_pattern == requested_pattern,

            (
                Capability::GitWrite {
                    repo_root: granted_root,
                },
                Capability::GitRead {
                    repo_root: requested_root,
                },
            )
            | (
                Capability::GitWrite {
                    repo_root: granted_root,
                },
                Capability::GitWrite {
                    repo_root: requested_root,
                },
            )
            | (
                Capability::GitRead {
                    repo_root: granted_root,
                },
                Capability::GitRead {
                    repo_root: requested_root,
                },
            ) => Self::validate_fs_access(requested_root, granted_root),

            (
                Capability::ContainerRun {
                    allowed_image: granted_image,
                },
                Capability::ContainerRun {
                    allowed_image: requested_image,
                },
            ) => granted_image == "*" || granted_image == requested_image,

            (
                Capability::HardwareAccess {
                    device_node: granted_node,
                    read_only: granted_read_only,
                },
                Capability::HardwareAccess {
                    device_node: requested_node,
                    read_only: requested_read_only,
                },
            ) => granted_node == requested_node && (*requested_read_only || !granted_read_only),

            (
                Capability::NetworkBind {
                    bind_addr: granted_addr,
                    max_port: granted_max_port,
                },
                Capability::NetworkBind {
                    bind_addr: requested_addr,
                    max_port: requested_max_port,
                },
            ) => granted_addr == requested_addr && requested_max_port <= granted_max_port,

            (
                Capability::DomainAccess {
                    namespace: granted_namespace,
                    read_only: granted_read_only,
                },
                Capability::DomainAccess {
                    namespace: requested_namespace,
                    read_only: requested_read_only,
                },
            ) => {
                granted_namespace == requested_namespace
                    && (*requested_read_only || !granted_read_only)
            }

            // Reconciliation authority is exact-task: there is no meaningful
            // containment between two task identifiers.
            (
                Capability::SystemReconciliation {
                    task_id: granted_task,
                },
                Capability::SystemReconciliation {
                    task_id: requested_task,
                },
            ) => granted_task == requested_task,

            _ => false,
        }
    }
}

// ── Authorization policy ──────────────────────────────────────────────────────

/// One standing rule: `agent_id` may hold a capability bounded by `capability`
/// until `not_after` (inclusive of the policy's own expiry).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRule {
    /// Exact agent identifier, or `"*"` for every agent.
    pub agent_id: String,
    /// Maximum scope this rule is willing to authorize.
    pub capability: Capability,
    /// Optional time bound for the rule itself.
    pub not_after: Option<DateTime<Utc>>,
}

impl CapabilityRule {
    pub fn for_agent(agent_id: impl Into<String>, capability: Capability) -> Self {
        Self {
            agent_id: agent_id.into(),
            capability,
            not_after: None,
        }
    }

    pub fn with_expiry(mut self, not_after: DateTime<Utc>) -> Self {
        self.not_after = Some(not_after);
        self
    }

    fn applies_to(&self, agent_id: &str) -> bool {
        self.agent_id == "*" || self.agent_id == agent_id
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.not_after.is_some_and(|not_after| now >= not_after)
    }
}

/// Immutable snapshot of the capability policy currently in force.
///
/// Recovery re-evaluates against *this*, never against the in-memory grant that
/// existed before the crash.  A grant is evidence that authorization once
/// happened; it is not evidence that authorization still holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationPolicy {
    policy_id: String,
    version: u64,
    updated_at: DateTime<Utc>,
    rules: Vec<CapabilityRule>,
    revoked_agents: BTreeSet<String>,
}

impl AuthorizationPolicy {
    pub fn new(policy_id: impl Into<String>, version: u64) -> Self {
        Self {
            policy_id: policy_id.into(),
            version,
            updated_at: Utc::now(),
            rules: Vec::new(),
            revoked_agents: BTreeSet::new(),
        }
    }

    pub fn with_rule(mut self, rule: CapabilityRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn with_rules(mut self, rules: impl IntoIterator<Item = CapabilityRule>) -> Self {
        self.rules.extend(rules);
        self
    }

    /// Permanently revoke every capability held by `agent_id`.
    pub fn with_revoked_agent(mut self, agent_id: impl Into<String>) -> Self {
        self.revoked_agents.insert(agent_id.into());
        self
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn is_agent_revoked(&self, agent_id: &str) -> bool {
        self.revoked_agents.contains(agent_id)
    }

    /// Evaluate a single capability request against the policy.
    pub fn evaluate(&self, agent_id: &str, capability: &Capability) -> CapabilityVerdict {
        self.evaluate_at(agent_id, capability, Utc::now())
    }

    fn evaluate_at(
        &self,
        agent_id: &str,
        capability: &Capability,
        now: DateTime<Utc>,
    ) -> CapabilityVerdict {
        if self.revoked_agents.contains(agent_id) {
            return CapabilityVerdict::Denied {
                reason: format!("agent '{agent_id}' is revoked by policy {}", self.policy_id),
            };
        }

        let mut saw_expired_rule = false;
        for rule in &self.rules {
            if !rule.applies_to(agent_id) {
                continue;
            }
            if rule.is_expired(now) {
                saw_expired_rule = true;
                continue;
            }
            if PolicyValidator::capability_covers(&rule.capability, capability) {
                return CapabilityVerdict::Permitted;
            }
        }

        CapabilityVerdict::Denied {
            reason: if saw_expired_rule {
                format!(
                    "capability {:?} is only granted by expired rules in policy {}",
                    capability, self.policy_id
                )
            } else {
                format!(
                    "capability {:?} is not granted to agent '{agent_id}' by policy {} v{}",
                    capability, self.policy_id, self.version
                )
            },
        }
    }

    /// Evaluate a whole capability set.  Fails closed on the first denial and
    /// on an empty set (a request that needs nothing is not a request).
    pub fn authorize(&self, agent_id: &str, capabilities: &[Capability]) -> AuthorizationOutcome {
        if capabilities.is_empty() {
            return AuthorizationOutcome::Denied {
                reason: "no capabilities were requested; refusing an unbounded authorization"
                    .to_string(),
                denied_capability: None,
            };
        }

        for capability in capabilities {
            if let CapabilityVerdict::Denied { reason } = self.evaluate(agent_id, capability) {
                return AuthorizationOutcome::Denied {
                    reason,
                    denied_capability: Some(capability.clone()),
                };
            }
        }

        AuthorizationOutcome::Granted {
            capabilities: capabilities.to_vec(),
            policy_id: self.policy_id.clone(),
            policy_version: self.version,
        }
    }

    /// Compare a recorded decision context against the live policy.
    pub fn drift_since(&self, policy_id: &str, policy_version: u64) -> PolicyDrift {
        if self.policy_id != policy_id {
            PolicyDrift::DifferentPolicy {
                recorded_policy_id: policy_id.to_string(),
                active_policy_id: self.policy_id.clone(),
            }
        } else if self.version != policy_version {
            PolicyDrift::VersionChanged {
                recorded_version: policy_version,
                active_version: self.version,
            }
        } else {
            PolicyDrift::Unchanged
        }
    }
}

impl Default for AuthorizationPolicy {
    fn default() -> Self {
        Self::new("skyos-default-policy", 1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityVerdict {
    Permitted,
    Denied { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Granted {
        capabilities: Vec<Capability>,
        policy_id: String,
        policy_version: u64,
    },
    Denied {
        reason: String,
        denied_capability: Option<Capability>,
    },
}

impl AuthorizationOutcome {
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

/// How the policy in force differs from the policy that authorized the
/// interrupted invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDrift {
    Unchanged,
    VersionChanged {
        recorded_version: u64,
        active_version: u64,
    },
    DifferentPolicy {
        recorded_policy_id: String,
        active_policy_id: String,
    },
}

impl PolicyDrift {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::VersionChanged { .. } => "version_changed",
            Self::DifferentPolicy { .. } => "different_policy",
        }
    }
}

/// Convenience constructor used by the CLI and tests: a policy that grants the
/// listed capabilities to one agent.
pub fn policy_for_agent(
    policy_id: impl Into<String>,
    version: u64,
    agent_id: impl Into<String>,
    capabilities: impl IntoIterator<Item = Capability>,
) -> AuthorizationPolicy {
    let agent_id = agent_id.into();
    AuthorizationPolicy::new(policy_id, version).with_rules(
        capabilities
            .into_iter()
            .map(|capability| CapabilityRule::for_agent(agent_id.clone(), capability)),
    )
}

/// Helper for building a filesystem-rooted policy rule.
pub fn fs_read_rule(agent_id: &str, root: impl Into<PathBuf>) -> CapabilityRule {
    CapabilityRule::for_agent(agent_id, Capability::FileSystemRead { root: root.into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AuthorizationPolicy {
        AuthorizationPolicy::new("test-policy", 3)
            .with_rule(CapabilityRule::for_agent(
                "agent-a",
                Capability::FileSystemWrite {
                    root: PathBuf::from("/repo"),
                },
            ))
            .with_rule(CapabilityRule::for_agent(
                "agent-a",
                Capability::GitWrite {
                    repo_root: PathBuf::from("/repo"),
                },
            ))
    }

    #[test]
    fn narrower_scope_is_permitted_and_wider_scope_is_denied() {
        let policy = policy();

        assert_eq!(
            policy.evaluate(
                "agent-a",
                &Capability::FileSystemWrite {
                    root: PathBuf::from("/repo/src/lib")
                }
            ),
            CapabilityVerdict::Permitted
        );

        assert!(matches!(
            policy.evaluate(
                "agent-a",
                &Capability::FileSystemWrite {
                    root: PathBuf::from("/elsewhere")
                }
            ),
            CapabilityVerdict::Denied { .. }
        ));
    }

    #[test]
    fn git_write_rule_covers_git_read_but_not_the_reverse() {
        let policy = AuthorizationPolicy::new("p", 1).with_rule(CapabilityRule::for_agent(
            "a",
            Capability::GitRead {
                repo_root: PathBuf::from("/repo"),
            },
        ));

        assert_eq!(
            policy.evaluate(
                "a",
                &Capability::GitRead {
                    repo_root: PathBuf::from("/repo")
                }
            ),
            CapabilityVerdict::Permitted
        );
        assert!(matches!(
            policy.evaluate(
                "a",
                &Capability::GitWrite {
                    repo_root: PathBuf::from("/repo")
                }
            ),
            CapabilityVerdict::Denied { .. }
        ));
    }

    #[test]
    fn agents_are_isolated_from_each_other() {
        let policy = policy();
        assert!(matches!(
            policy.evaluate(
                "agent-b",
                &Capability::FileSystemWrite {
                    root: PathBuf::from("/repo")
                }
            ),
            CapabilityVerdict::Denied { .. }
        ));
    }

    #[test]
    fn revoked_agent_is_denied_even_with_a_matching_rule() {
        let policy = policy().with_revoked_agent("agent-a");
        assert!(matches!(
            policy.evaluate(
                "agent-a",
                &Capability::FileSystemWrite {
                    root: PathBuf::from("/repo")
                }
            ),
            CapabilityVerdict::Denied { .. }
        ));
    }

    #[test]
    fn expired_rule_does_not_authorize() {
        let policy = AuthorizationPolicy::new("p", 2).with_rule(
            CapabilityRule::for_agent(
                "a",
                Capability::FileSystemRead {
                    root: PathBuf::from("/repo"),
                },
            )
            .with_expiry(Utc::now() - chrono::Duration::seconds(1)),
        );

        let verdict = policy.evaluate(
            "a",
            &Capability::FileSystemRead {
                root: PathBuf::from("/repo"),
            },
        );
        match verdict {
            CapabilityVerdict::Denied { reason } => assert!(reason.contains("expired")),
            CapabilityVerdict::Permitted => panic!("expired rule must not authorize"),
        }
    }

    #[test]
    fn empty_capability_set_is_refused() {
        let policy = policy();
        assert!(!policy.authorize("agent-a", &[]).is_granted());
    }

    #[test]
    fn drift_detects_version_and_identity_changes() {
        let policy = policy();
        assert_eq!(policy.drift_since("test-policy", 3), PolicyDrift::Unchanged);
        assert!(matches!(
            policy.drift_since("test-policy", 2),
            PolicyDrift::VersionChanged { .. }
        ));
        assert!(matches!(
            policy.drift_since("other", 3),
            PolicyDrift::DifferentPolicy { .. }
        ));
    }
}
