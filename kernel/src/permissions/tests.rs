#[cfg(test)]
mod tests {
    use crate::permissions::engine::PolicyEngine;
    use crate::permissions::issuer::GrantIssuer;
    use crate::permissions::types::{Capability, ToolInvocationRequest};
    use chrono::Duration;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn path_traversal_attack_blocked() {
        let issuer = GrantIssuer::new();
        let task_id = Uuid::new_v4();
        let root = PathBuf::from("C:\\workspace\\project");

        let grant = issuer.issue_grant(
            "coder_agent",
            task_id,
            vec![Capability::FileSystemRead { root: root.clone() }],
            None,
        );

        let engine = PolicyEngine::new(None);

        // Adversarial path traversal attempt
        let attack_request = ToolInvocationRequest::FileSystemRead {
            requested_path: PathBuf::from("C:\\workspace\\project\\..\\..\\Windows\\System32"),
        };

        let decision = engine.evaluate(&grant, &attack_request);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn process_exec_arg_prefix_and_workdir_enforced() {
        let issuer = GrantIssuer::new();
        let task_id = Uuid::new_v4();
        let allowed_workdir = PathBuf::from("C:\\workspace\\project");

        let grant = issuer.issue_grant(
            "coder_agent",
            task_id,
            vec![Capability::ProcessExec {
                program: "cargo".to_string(),
                allowed_args_prefix: vec!["test".to_string()],
                allowed_workdir: allowed_workdir.clone(),
            }],
            None,
        );

        let engine = PolicyEngine::new(None);

        // 1. Valid invocation: cargo test
        let valid_req = ToolInvocationRequest::ProcessExec {
            program: "cargo".to_string(),
            args: vec!["test".to_string(), "--lib".to_string()],
            workdir: allowed_workdir.clone(),
        };
        assert!(engine.evaluate(&grant, &valid_req).is_allowed());

        // 2. Disallowed command prefix: cargo build
        let invalid_prefix_req = ToolInvocationRequest::ProcessExec {
            program: "cargo".to_string(),
            args: vec!["build".to_string()],
            workdir: allowed_workdir,
        };
        assert!(!engine.evaluate(&grant, &invalid_prefix_req).is_allowed());
    }

    #[test]
    fn expired_or_revoked_grant_denied() {
        let issuer = GrantIssuer::new();
        let task_id = Uuid::new_v4();

        // Expired grant (TTL negative)
        let expired_grant = issuer.issue_grant(
            "coder_agent",
            task_id,
            vec![Capability::FileSystemRead {
                root: PathBuf::from("C:\\workspace"),
            }],
            Some(Duration::minutes(-5)),
        );

        let engine = PolicyEngine::new(None);
        let request = ToolInvocationRequest::FileSystemRead {
            requested_path: PathBuf::from("C:\\workspace\\file.txt"),
        };
        assert!(!engine.evaluate(&expired_grant, &request).is_allowed());

        // Revoked grant
        let active_grant = issuer.issue_grant(
            "coder_agent",
            task_id,
            vec![Capability::FileSystemRead {
                root: PathBuf::from("C:\\workspace"),
            }],
            None,
        );
        issuer.revoke_grant(&active_grant.grant_id).unwrap();
        let updated_grant = issuer.get_grant(&active_grant.grant_id).unwrap();
        assert!(!engine.evaluate(&updated_grant, &request).is_allowed());
    }
}
