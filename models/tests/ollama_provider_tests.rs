//! Roadmap Phase 5 — Ollama adapter contract tests.
//!
//! Every test runs against a canned local HTTP server: no Ollama daemon and no
//! outbound network are required, so these stay green offline. They pin the
//! adapter's promises — exact request shape, structured proposal parsing, and a
//! *typed* failure for each way the service can go wrong (unreachable, stalled,
//! missing model, server error, non-JSON body, malformed proposal).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use models::ollama::{OllamaError, OllamaModelProvider};
use models::provider::{ActionProposal, ModelProvider, StepHistory};
use serde_json::{Value, json};
use tools::registry::ToolSchema;

// ── Canned Ollama server ─────────────────────────────────────────────────────

struct RecordedRequest {
    path: String,
    body: String,
}

/// Serve `responses` (status line + body) once per connection, recording each
/// request. Returns the base URL and the recorded requests.
fn spawn_server(responses: Vec<(&'static str, String)>) -> (String, Receiver<RecordedRequest>) {
    spawn_server_with_delay(responses, Duration::ZERO)
}

fn spawn_server_with_delay(
    responses: Vec<(&'static str, String)>,
    delay: Duration,
) -> (String, Receiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake ollama");
    let addr = listener.local_addr().expect("local addr");
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let request = read_request(&mut stream);
            let _ = sender.send(request);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    (format!("http://{addr}"), receiver)
}

fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break buffer.len(),
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end.min(buffer.len())]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);

    while buffer.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }

    RecordedRequest {
        path: headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string(),
        body: String::from_utf8_lossy(&buffer[header_end..]).to_string(),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// An endpoint that refuses connections (bind, capture, release).
fn closed_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{addr}")
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn schemas() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            tool_id: "filesystem".into(),
            operation_id: "read_file".into(),
            description: "Read a file.".into(),
            required_capability: "FileSystemRead".into(),
            parameters_schema: json!({
                "type": "object",
                "properties": { "relative_path": { "type": "string" } },
                "required": ["relative_path"]
            }),
        },
        ToolSchema {
            tool_id: "git".into(),
            operation_id: "commit".into(),
            description: "Commit staged changes.".into(),
            required_capability: "GitWrite".into(),
            parameters_schema: json!({
                "type": "object",
                "properties": { "message": { "type": "string" } },
                "required": ["message"]
            }),
        },
    ]
}

fn proposal_content(proposal: Value) -> String {
    json!({
        "model": "test-model",
        "message": { "role": "assistant", "content": proposal.to_string() },
        "done": true,
        "done_reason": "stop"
    })
    .to_string()
}

fn provider(endpoint: &str) -> OllamaModelProvider {
    OllamaModelProvider::new("test-model")
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(5))
}

fn error_of(error: anyhow::Error) -> OllamaError {
    error
        .downcast::<OllamaError>()
        .expect("error must carry the typed OllamaError")
}

// ── Happy path ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_chat_response_is_parsed_into_an_action_proposal() {
    let proposal = json!({
        "tool_id": "filesystem",
        "operation_id": "read_file",
        "parameters": { "relative_path": "README.md" },
        "is_complete": false
    });
    let (endpoint, _requests) = spawn_server(vec![("200 OK", proposal_content(proposal))]);

    let result = provider(&endpoint)
        .propose_action("inspect the repository", &schemas(), &[])
        .await
        .expect("valid response must parse");

    assert_eq!(result.tool_id, "filesystem");
    assert_eq!(result.operation_id, "read_file");
    assert!(!result.is_complete);
    assert_eq!(result.parameters["relative_path"], "README.md");
}

#[tokio::test]
async fn the_request_carries_the_model_stream_flag_and_tool_catalogue() {
    let proposal = json!({
        "tool_id": "git",
        "operation_id": "commit",
        "parameters": { "message": "docs: update readme" },
        "is_complete": false
    });
    let (endpoint, requests) = spawn_server(vec![("200 OK", proposal_content(proposal))]);

    let history = vec![StepHistory {
        step_number: 1,
        tool_id: "filesystem".into(),
        operation_id: "read_file".into(),
        status: "Succeeded".into(),
        output_snippet: Some("README contents".into()),
        error_message: None,
    }];

    provider(&endpoint)
        .propose_action("write the changelog", &schemas(), &history)
        .await
        .expect("valid response must parse");

    let request = requests.recv().expect("request recorded");
    assert_eq!(request.path, "/api/chat");

    let body: Value = serde_json::from_str(&request.body).expect("request body is JSON");
    assert_eq!(body["model"], "test-model");
    assert_eq!(body["stream"], false);
    assert_eq!(body["format"], "json");
    assert_eq!(body["messages"][0]["role"], "system");

    let user = body["messages"][1]["content"]
        .as_str()
        .expect("user content");
    assert!(
        user.contains("write the changelog"),
        "task title must reach the prompt"
    );
    assert!(
        user.contains("filesystem") && user.contains("read_file"),
        "catalogue must be listed"
    );
    assert!(
        user.contains("required_capability"),
        "capability must be visible to the model"
    );
    assert!(user.contains("README contents"), "history must be fed back");
}

#[tokio::test]
async fn markdown_fenced_model_output_is_unwrapped() {
    let fenced = proposal_content(json!({
        "tool_id": "filesystem",
        "operation_id": "read_file",
        "parameters": { "relative_path": "Cargo.toml" },
        "is_complete": false
    }));
    // Wrap the assistant content in a fence, as models often do despite instructions.
    let mut value: Value = serde_json::from_str(&fenced).expect("fixture json");
    let inner = value["message"]["content"]
        .as_str()
        .expect("content")
        .to_string();
    value["message"]["content"] = json!(format!("```json\n{inner}\n```"));

    let (endpoint, _requests) = spawn_server(vec![("200 OK", value.to_string())]);

    let result = provider(&endpoint)
        .propose_action("read a file", &schemas(), &[])
        .await
        .expect("fenced output must still parse");

    assert_eq!(result.tool_id, "filesystem");
}

#[tokio::test]
async fn completion_proposals_skip_catalogue_validation() {
    let proposal = json!({
        "tool_id": "__complete__",
        "operation_id": "__complete__",
        "parameters": {},
        "is_complete": true
    });
    let (endpoint, _requests) = spawn_server(vec![("200 OK", proposal_content(proposal))]);

    let result = provider(&endpoint)
        .propose_action("done", &schemas(), &[])
        .await
        .expect("completion marker is not a tool call");

    assert!(result.is_complete);
}

// ── Failure taxonomy ─────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreachable_endpoint_reports_connection_failed() {
    let endpoint = closed_endpoint();

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("connection must fail"),
    );

    match error {
        OllamaError::ConnectionFailed {
            endpoint: reported,
            detail,
        } => {
            assert_eq!(reported, endpoint);
            assert!(!detail.is_empty(), "the transport reason must be preserved");
        }
        other => panic!("expected ConnectionFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn a_stalled_model_reports_request_timeout() {
    let (endpoint, _requests) = spawn_server_with_delay(
        vec![(
            "200 OK",
            proposal_content(
                json!({"tool_id":"git","operation_id":"commit","parameters":{},"is_complete":false}),
            ),
        )],
        Duration::from_secs(3),
    );

    let error = error_of(
        OllamaModelProvider::new("test-model")
            .with_endpoint(&endpoint)
            .with_timeout(Duration::from_millis(250))
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("stalled response must time out"),
    );

    match error {
        OllamaError::RequestTimeout { timeout_ms, .. } => assert_eq!(timeout_ms, 250),
        other => panic!("expected RequestTimeout, got {other:?}"),
    }
}

#[tokio::test]
async fn a_missing_model_reports_model_unavailable() {
    let body = json!({ "error": "model 'test-model' not found, try pulling it first" }).to_string();
    let (endpoint, _requests) = spawn_server(vec![("404 Not Found", body)]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("missing model must fail"),
    );

    match error {
        OllamaError::ModelUnavailable { model, detail } => {
            assert_eq!(model, "test-model");
            assert!(
                detail.contains("not found"),
                "server detail must survive: {detail}"
            );
        }
        other => panic!("expected ModelUnavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn a_bare_not_found_is_an_api_error_not_a_missing_model() {
    let (endpoint, _requests) = spawn_server(vec![("404 Not Found", "page not found".to_string())]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("404 must fail"),
    );

    match error {
        OllamaError::ApiError { status, .. } => assert_eq!(status, 404),
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[tokio::test]
async fn a_server_error_reports_api_error() {
    let (endpoint, _requests) =
        spawn_server(vec![("500 Internal Server Error", "boom".to_string())]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("500 must fail"),
    );

    match error {
        OllamaError::ApiError { status, body } => {
            assert_eq!(status, 500);
            assert!(body.contains("boom"), "body must survive: {body}");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_json_body_reports_malformed_response() {
    let (endpoint, _requests) =
        spawn_server(vec![("200 OK", "<html>proxy error</html>".to_string())]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("non-JSON must fail"),
    );

    assert!(
        matches!(error, OllamaError::MalformedResponse { .. }),
        "expected MalformedResponse, got {error:?}"
    );
}

#[tokio::test]
async fn a_response_without_an_assistant_message_reports_malformed_response() {
    let body = json!({ "model": "test-model", "done": true }).to_string();
    let (endpoint, _requests) = spawn_server(vec![("200 OK", body)]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("missing message must fail"),
    );

    assert!(
        matches!(error, OllamaError::MalformedResponse { .. }),
        "expected MalformedResponse, got {error:?}"
    );
}

#[tokio::test]
async fn prose_that_is_not_a_proposal_reports_invalid_proposal() {
    let content = "I think we should read the README first, then commit.";
    let (endpoint, _requests) = spawn_server(vec![("200 OK", proposal_content(json!(content)))]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("prose must fail"),
    );

    match error {
        OllamaError::InvalidProposal { detail } => {
            assert!(
                detail.contains("I think"),
                "offending output must be surfaced: {detail}"
            )
        }
        other => panic!("expected InvalidProposal, got {other:?}"),
    }
}

#[tokio::test]
async fn parameters_that_are_not_an_object_are_rejected() {
    let proposal = json!({
        "tool_id": "git",
        "operation_id": "commit",
        "parameters": "message: please",
        "is_complete": false
    });
    let (endpoint, _requests) = spawn_server(vec![("200 OK", proposal_content(proposal))]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("scalar parameters must fail"),
    );

    assert!(
        matches!(error, OllamaError::InvalidProposal { .. }),
        "expected InvalidProposal, got {error:?}"
    );
}

#[tokio::test]
async fn a_proposal_for_an_unknown_tool_is_rejected_before_dispatch() {
    let proposal = json!({
        "tool_id": "kernel",
        "operation_id": "sudo",
        "parameters": {},
        "is_complete": false
    });
    let (endpoint, _requests) = spawn_server(vec![("200 OK", proposal_content(proposal))]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &schemas(), &[])
            .await
            .expect_err("invented tools must fail"),
    );

    match error {
        OllamaError::UnknownTool {
            tool_id,
            operation_id,
        } => {
            assert_eq!(tool_id, "kernel");
            assert_eq!(operation_id, "sudo");
        }
        other => panic!("expected UnknownTool, got {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_served_proposal_is_rejected() {
    // An empty catalogue is legitimate (no tools authorized for this task).
    let proposal = json!({
        "tool_id": "   ",
        "operation_id": "read_file",
        "parameters": {},
        "is_complete": false
    });
    let (endpoint, _requests) = spawn_server(vec![("200 OK", proposal_content(proposal))]);

    let error = error_of(
        provider(&endpoint)
            .propose_action("task", &[], &[])
            .await
            .expect_err("blank tool id must fail"),
    );

    assert!(
        matches!(error, OllamaError::InvalidProposal { .. }),
        "expected InvalidProposal, got {error:?}"
    );
}

// ── Contract shape ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_adapter_satisfies_the_model_provider_contract() {
    fn assert_provider<P: ModelProvider>(_provider: &P) {}
    assert_provider(&OllamaModelProvider::new("llama3"));

    // The error type is what callers downcast to; it must implement Error.
    let _: &dyn std::error::Error = &OllamaError::MalformedResponse {
        detail: "x".to_string(),
    };

    let _ = ActionProposal {
        tool_id: "__complete__".into(),
        operation_id: "__complete__".into(),
        parameters: json!({}),
        is_complete: true,
    };
}
