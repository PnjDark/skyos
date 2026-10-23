use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tools::registry::ToolSchema;

/// The next structured action proposed by the reasoning engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    pub tool_id: String,
    pub operation_id: String,
    pub parameters: Value,
    pub is_complete: bool,
}

/// Structured summary of an observed execution step passed back to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepHistory {
    pub step_number: usize,
    pub tool_id: String,
    pub operation_id: String,
    pub status: String,
    pub output_snippet: Option<String>,
    pub error_message: Option<String>,
}

/// Abstract contract for LLM reasoning engines (Local Ollama, OpenAI, Anthropic, Gemini, Mocks).
#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn propose_action(
        &self,
        task_title: &str,
        available_schemas: &[ToolSchema],
        history: &[StepHistory],
    ) -> anyhow::Result<ActionProposal>;
}

/// Thread-safe scripted provider for deterministic testing of the execution loop.
#[derive(Clone, Default)]
pub struct ScriptedModelProvider {
    responses: Arc<Mutex<Vec<anyhow::Result<ActionProposal>>>>,
}

impl ScriptedModelProvider {
    pub fn new(responses: Vec<anyhow::Result<ActionProposal>>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses)),
        }
    }

    pub fn push_response(&self, res: anyhow::Result<ActionProposal>) {
        let mut lock = self
            .responses
            .lock()
            .expect("ScriptedModelProvider poisoned");
        lock.push(res);
    }
}

#[async_trait]
impl ModelProvider for ScriptedModelProvider {
    async fn propose_action(
        &self,
        _task_title: &str,
        _available_schemas: &[ToolSchema],
        _history: &[StepHistory],
    ) -> anyhow::Result<ActionProposal> {
        let mut lock = self
            .responses
            .lock()
            .expect("ScriptedModelProvider poisoned");
        if lock.is_empty() {
            anyhow::bail!("ScriptedModelProvider has no remaining scheduled responses");
        }
        lock.remove(0)
    }
}
