use crate::types::{ToolContext, ToolOutput, ToolResult, ToolStatus};
use kernel::domain::{DomainError, DomainStore};
use kernel::events::EventBus;
use kernel::permissions::engine::PolicyEngine;
use kernel::permissions::issuer::GrantIssuer;
use kernel::permissions::types::{CapabilityGrant, PolicyDecision, ToolInvocationRequest};
use serde_json::json;

pub const EVENT_DOMAIN_COMPLETED: &str = "DomainOperationCompleted";
pub const EVENT_DOMAIN_FAILED: &str = "DomainOperationFailed";

pub struct DomainToolExecutor<'a> {
    event_bus: &'a EventBus,
    domain_store: &'a DomainStore,
    #[allow(dead_code)]
    grant_issuer: &'a GrantIssuer,
}

impl<'a> DomainToolExecutor<'a> {
    pub fn new(
        event_bus: &'a EventBus,
        domain_store: &'a DomainStore,
        grant_issuer: &'a GrantIssuer,
    ) -> Self {
        Self {
            event_bus,
            domain_store,
            grant_issuer,
        }
    }

    /// Execute a SELECT query against a registered domain namespace.
    pub fn query(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        namespace: &str,
        sql: &str,
        params: Vec<serde_json::Value>,
    ) -> ToolResult {
        let req = ToolInvocationRequest::DomainAccess {
            namespace: namespace.to_string(),
            read_only: true,
        };
        if let Some(denied) = self.check_policy(ctx, grant, &req) {
            return denied;
        }

        match self.domain_store.query(namespace, sql, &params) {
            Ok(rows) => {
                if let Err(e) = self.event_bus.emit_event(
                    Some(&ctx.task_id.to_string()),
                    EVENT_DOMAIN_COMPLETED,
                    json!({
                        "invocation_id": ctx.invocation_id,
                        "operation": "query",
                        "namespace": namespace,
                        "row_count": rows.len(),
                    }),
                ) {
                    return self.fail(ctx, format!("Audit persistence failure: {e}"));
                }
                ToolResult {
                    invocation_id: ctx.invocation_id,
                    status: ToolStatus::Succeeded,
                    output: ToolOutput::Text(serde_json::to_string(&rows).unwrap_or_default()),
                    artifact: None,
                    error_message: None,
                }
            }
            Err(e) => self.fail(ctx, format_domain_error(namespace, e)),
        }
    }

    /// Execute an INSERT/UPDATE/DELETE against a registered domain namespace.
    pub fn mutate(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        namespace: &str,
        sql: &str,
        params: Vec<serde_json::Value>,
    ) -> ToolResult {
        let req = ToolInvocationRequest::DomainAccess {
            namespace: namespace.to_string(),
            read_only: false,
        };
        if let Some(denied) = self.check_policy(ctx, grant, &req) {
            return denied;
        }

        match self.domain_store.mutate(namespace, sql, &params) {
            Ok(affected) => {
                if let Err(e) = self.event_bus.emit_event(
                    Some(&ctx.task_id.to_string()),
                    EVENT_DOMAIN_COMPLETED,
                    json!({
                        "invocation_id": ctx.invocation_id,
                        "operation": "mutate",
                        "namespace": namespace,
                        "rows_affected": affected,
                    }),
                ) {
                    return self.fail(ctx, format!("Audit persistence failure: {e}"));
                }
                ToolResult {
                    invocation_id: ctx.invocation_id,
                    status: ToolStatus::Succeeded,
                    output: ToolOutput::Text(format!("{affected} row(s) affected")),
                    artifact: None,
                    error_message: None,
                }
            }
            Err(e) => self.fail(ctx, format_domain_error(namespace, e)),
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn check_policy(
        &self,
        ctx: &ToolContext,
        grant: &CapabilityGrant,
        req: &ToolInvocationRequest,
    ) -> Option<ToolResult> {
        let engine = PolicyEngine::new(Some(self.event_bus));
        match engine.evaluate_checked(grant, req) {
            Ok(PolicyDecision::Allow { .. }) => None,
            Ok(PolicyDecision::Deny { reason }) => {
                Some(self.fail(ctx, format!("Policy Engine denied domain access: {reason}")))
            }
            Err(e) => Some(self.fail(ctx, format!("Failed to persist domain audit: {e}"))),
        }
    }

    fn fail(&self, ctx: &ToolContext, message: String) -> ToolResult {
        let _ = self.event_bus.emit_event(
            Some(&ctx.task_id.to_string()),
            EVENT_DOMAIN_FAILED,
            json!({ "invocation_id": ctx.invocation_id, "error": message }),
        );
        ToolResult {
            invocation_id: ctx.invocation_id,
            status: ToolStatus::Failed,
            output: ToolOutput::Empty,
            artifact: None,
            error_message: Some(message),
        }
    }
}

fn format_domain_error(namespace: &str, e: DomainError) -> String {
    format!("Domain '{namespace}' error: {e}")
}
