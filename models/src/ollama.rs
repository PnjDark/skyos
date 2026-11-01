//! Roadmap Phase 5 (model abstraction) — Ollama provider adapter.
//!
//! This is the first concrete [`ModelProvider`]. The trait stays authoritative:
//! the adapter adds no fallback semantics, invents no proposals, and never
//! fabricates a response when the service cannot be reached — every failure
//! surfaces as a typed [`OllamaError`] inside the trait's `anyhow::Result`, so
//! callers can downcast instead of pattern-matching on prose.
//!
//! # Contract
//!
//! * `POST {endpoint}/api/chat` with `stream: false` and `format: "json"`.
//! * The model's message content must be a single JSON object deserializable
//!   into [`ActionProposal`].
//! * A proposal naming a tool that is not in the supplied catalogue is
//!   rejected here, not deferred to the dispatcher. Completion proposals are
//!   exempt because the executor checks `is_complete` before dispatch.
//!
//! # Transport
//!
//! The blocking HTTP client runs on Tokio's blocking pool via
//! [`tokio::task::spawn_blocking`], so a slow local model never stalls the
//! executor's worker thread. This build enables only `ureq`'s `json` feature —
//! plain `http://` endpoints (Ollama's default) work; TLS endpoints do not, and
//! fail as [`OllamaError::ConnectionFailed`] rather than silently degrading.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tools::registry::ToolSchema;

use crate::provider::{ActionProposal, ModelProvider, StepHistory};

/// Ollama's out-of-the-box local endpoint.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";

/// Default request budget.
///
/// Deliberately below the executor's own 60 s `propose_action` timeout
/// (`agents/src/executor.rs`) so a stalled model produces a typed
/// [`OllamaError::RequestTimeout`] instead of the generic executor timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

/// The `tool_id`/`operation_id` pair the executor treats as "task finished"
/// (`agents/tests/executor_tests.rs`). Completion is evaluated before dispatch,
/// so these placeholders are never validated against the tool catalogue.
const COMPLETION_MARKER: &str = "__complete__";

/// Every way the Ollama adapter can fail, in one place.
///
/// The `ModelProvider` trait returns `anyhow::Result`, so these are carried as
/// the underlying error type: `err.downcast_ref::<OllamaError>()`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OllamaError {
    /// The endpoint refused the connection, or the transport failed.
    #[error("ollama endpoint {endpoint} is unreachable: {detail}")]
    ConnectionFailed { endpoint: String, detail: String },

    /// The request exceeded the configured budget before a response arrived.
    #[error("ollama request to {endpoint} timed out after {timeout_ms} ms")]
    RequestTimeout { endpoint: String, timeout_ms: u64 },

    /// A non-2xx HTTP response that does not indicate a missing model.
    #[error("ollama returned HTTP {status}: {body}")]
    ApiError { status: u16, body: String },

    /// Ollama does not have the requested model (pull required).
    #[error("model {model:?} is not available: {detail}")]
    ModelUnavailable { model: String, detail: String },

    /// The transport answered, but the payload is not a chat response.
    #[error("malformed ollama response: {detail}")]
    MalformedResponse { detail: String },

    /// The model answered with JSON that is not an `ActionProposal`.
    #[error("model output is not a valid action proposal: {detail}")]
    InvalidProposal { detail: String },

    /// The model proposed an operation that is not in the supplied catalogue.
    #[error("model proposed unknown tool {tool_id}.{operation_id}")]
    UnknownTool {
        tool_id: String,
        operation_id: String,
    },
}

/// A concrete [`ModelProvider`] backed by a local (or remote) Ollama server.
#[derive(Debug, Clone)]
pub struct OllamaModelProvider {
    endpoint: String,
    model: String,
    request_timeout: Duration,
}

impl OllamaModelProvider {
    /// Connect to the default Ollama endpoint with `model` (e.g. `llama3`).
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            model: model.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Override the server root, e.g. `http://127.0.0.1:11434`. Trailing
    /// slashes are normalized away so the request URL is never `//api/chat`.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        self.endpoint = endpoint.trim_end_matches('/').to_string();
        self
    }

    /// Override the request budget. Must stay below the executor's own
    /// `propose_action` timeout for the typed error to win.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Build the `POST /api/chat` payload. `stream: false` keeps the reply to a
    /// single JSON body; `format: "json"` asks Ollama to constrain decoding.
    fn build_body(
        &self,
        task_title: &str,
        available_schemas: &[ToolSchema],
        history: &[StepHistory],
    ) -> String {
        let system = format!(
            "You are the action-selection engine of Sky OS, a capability-governed agent runtime. \
             You never execute anything yourself: you choose the next single action and the \
             runtime's permission engine decides whether it is allowed.\n\
             Reply with exactly one JSON object and nothing else — no prose, no markdown fences:\n\
             {{\"tool_id\": string, \"operation_id\": string, \"parameters\": object, \"is_complete\": boolean}}\n\
             Rules:\n\
             - tool_id and operation_id must both come from the tool catalogue provided below.\n\
             - parameters must be a JSON object matching that operation's parameters_schema.\n\
             - When the task is finished set is_complete to true and use the literal placeholders \
             \"{COMPLETION_MARKER}\" for tool_id and operation_id.\n\
             - Never invent a tool, and never claim an action succeeded.",
        );

        let user = json!({
            "task": task_title,
            "tool_catalogue": available_schemas.iter().map(|schema| json!({
                "tool_id": schema.tool_id,
                "operation_id": schema.operation_id,
                "description": schema.description,
                "required_capability": schema.required_capability,
                "parameters_schema": schema.parameters_schema,
            })).collect::<Vec<_>>(),
            "history": if history.is_empty() {
                Value::String("(no steps attempted yet)".to_string())
            } else {
                serde_json::to_value(history).unwrap_or(Value::Null)
            },
        });

        let request = ChatRequest {
            model: &self.model,
            stream: false,
            format: "json",
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system.to_string(),
                },
                ChatMessage {
                    role: "user",
                    content: serde_json::to_string_pretty(&user)
                        .unwrap_or_else(|_| task_title.to_string()),
                },
            ],
        };

        serde_json::to_string(&request).expect("ChatRequest serialization cannot fail")
    }

    /// Turn the assistant's message content into a validated proposal.
    fn parse_proposal(
        content: &str,
        available_schemas: &[ToolSchema],
    ) -> Result<ActionProposal, OllamaError> {
        let cleaned = strip_markdown_fence(content);
        let proposal: ActionProposal =
            serde_json::from_str(cleaned).map_err(|error| OllamaError::InvalidProposal {
                detail: format!("{error}; model output: {}", truncate(cleaned)),
            })?;

        if proposal.tool_id.trim().is_empty() {
            return Err(OllamaError::InvalidProposal {
                detail: "proposal has an empty tool_id".to_string(),
            });
        }
        if !matches!(proposal.parameters, Value::Object(_) | Value::Null) {
            return Err(OllamaError::InvalidProposal {
                detail: format!(
                    "parameters must be a JSON object, got {}",
                    proposal.parameters
                ),
            });
        }
        if proposal.is_complete {
            return Ok(proposal);
        }

        let known = available_schemas.iter().any(|schema| {
            schema.tool_id == proposal.tool_id && schema.operation_id == proposal.operation_id
        });
        if !known {
            return Err(OllamaError::UnknownTool {
                tool_id: proposal.tool_id,
                operation_id: proposal.operation_id,
            });
        }
        Ok(proposal)
    }

    /// Issue the HTTP request on the blocking pool and interpret the reply.
    async fn exchange(
        &self,
        task_title: &str,
        available_schemas: &[ToolSchema],
        history: &[StepHistory],
    ) -> Result<ActionProposal, OllamaError> {
        let body = self.build_body(task_title, available_schemas, history);
        let endpoint = self.endpoint.clone();
        let request_endpoint = self.endpoint.clone();
        let timeout = self.request_timeout;

        let (status, response_body) =
            tokio::task::spawn_blocking(move || post_chat(&request_endpoint, timeout, body))
                .await
                .map_err(|error| OllamaError::ConnectionFailed {
                    endpoint,
                    detail: format!("blocking request task failed: {error}"),
                })??;

        let content = decode_chat_response(status, &response_body, &self.model)?;
        Self::parse_proposal(&content, available_schemas)
    }
}

#[async_trait]
impl ModelProvider for OllamaModelProvider {
    async fn propose_action(
        &self,
        task_title: &str,
        available_schemas: &[ToolSchema],
        history: &[StepHistory],
    ) -> anyhow::Result<ActionProposal> {
        Ok(self
            .exchange(task_title, available_schemas, history)
            .await?)
    }
}

// ── Transport ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    stream: bool,
    format: &'a str,
    messages: Vec<ChatMessage>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    #[serde(default)]
    message: Option<ChatResponseMessage>,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    content: String,
}

/// Blocking `POST {endpoint}/api/chat`. Runs on Tokio's blocking pool.
fn post_chat(
    endpoint: &str,
    timeout: Duration,
    body: String,
) -> Result<(u16, String), OllamaError> {
    let url = format!("{endpoint}/api/chat");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        // Statuses are classified by `decode_chat_response`, which needs the
        // response body to tell a missing model from a broken server.
        .http_status_as_error(false)
        .build()
        .into();

    let mut response = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|error| map_transport_error(endpoint, timeout, error))?;

    let status = response.status();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|error| map_transport_error(endpoint, timeout, error))?;

    Ok((status.into(), body))
}

fn map_transport_error(endpoint: &str, timeout: Duration, error: ureq::Error) -> OllamaError {
    match error {
        ureq::Error::Timeout(_) => OllamaError::RequestTimeout {
            endpoint: endpoint.to_string(),
            timeout_ms: timeout.as_millis() as u64,
        },
        other => OllamaError::ConnectionFailed {
            endpoint: endpoint.to_string(),
            detail: other.to_string(),
        },
    }
}

/// Pull the assistant's message content out of a chat response.
fn decode_chat_response(status: u16, body: &str, model: &str) -> Result<String, OllamaError> {
    if !(200..300).contains(&status) {
        return Err(classify_http_error(status, body, model));
    }

    let value: Value =
        serde_json::from_str(body).map_err(|error| OllamaError::MalformedResponse {
            detail: format!(
                "response body is not JSON: {error}; body: {}",
                truncate(body)
            ),
        })?;

    if let Some(error) = value
        .get("error")
        .and_then(Value::as_str)
        .filter(|error| !error.trim().is_empty())
    {
        return Err(if describes_missing_model(error) {
            OllamaError::ModelUnavailable {
                model: model.to_string(),
                detail: error.to_string(),
            }
        } else {
            OllamaError::ApiError {
                status,
                body: error.to_string(),
            }
        });
    }

    let parsed: ChatResponse =
        serde_json::from_value(value).map_err(|error| OllamaError::MalformedResponse {
            detail: format!(
                "unexpected response shape: {error}; body: {}",
                truncate(body)
            ),
        })?;

    parsed
        .message
        .map(|message| message.content)
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(|| OllamaError::MalformedResponse {
            detail: format!(
                "response carries no assistant message; body: {}",
                truncate(body)
            ),
        })
}

/// Ollama reports a missing model as a 4xx with an `error` field naming the
/// model; a bare 404 (wrong path, proxy) is a plain [`OllamaError::ApiError`].
fn classify_http_error(status: u16, body: &str, model: &str) -> OllamaError {
    let detail = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| truncate(body));

    if describes_missing_model(&detail) {
        OllamaError::ModelUnavailable {
            model: model.to_string(),
            detail,
        }
    } else {
        OllamaError::ApiError {
            status,
            body: detail,
        }
    }
}

/// Ollama names the model in its error ("model 'llama3' not found, try
/// pulling it first", "no such model: x", "pull model manifest: …"). Requiring
/// the word "model" keeps a generic 404 page from being reported as a missing
/// model.
fn describes_missing_model(message: &str) -> bool {
    let lowered = message.to_lowercase();
    lowered.contains("model")
        && (lowered.contains("not found")
            || lowered.contains("no such")
            || lowered.contains("pull"))
}

/// Models frequently wrap JSON in a ``` fence despite instructions; unwrap it,
/// but never reach past a fence into surrounding prose.
fn strip_markdown_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(after_fence) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let body = match after_fence.find('\n') {
        Some(index) => &after_fence[index + 1..],
        None => return trimmed,
    };
    match body.rfind("```") {
        Some(end) => body[..end].trim(),
        None => body.trim(),
    }
}

fn truncate(text: &str) -> String {
    const LIMIT: usize = 400;
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(LIMIT).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}
