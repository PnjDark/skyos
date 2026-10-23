use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::persistence::{
    db::{DatabaseConnectionPool, DatabaseError},
    migrations::M1_INITIAL_SCHEMA,
};

#[derive(Debug, Error)]
pub enum EventError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type EventResult<T> = Result<T, EventError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub event_id: String,
    pub task_id: String,
    pub event_type: String,
    pub payload: HashMap<String, serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct EventBus {
    connection: DatabaseConnectionPool,
}

impl EventBus {
    pub fn open(path: impl AsRef<Path>) -> EventResult<Self> {
        let path = path.as_ref();
        let connection = DatabaseConnectionPool::open(path)?;
        let connection = connection.connection()?;
        connection.execute_batch(M1_INITIAL_SCHEMA)?;

        Ok(Self {
            connection: DatabaseConnectionPool::open(path)?,
        })
    }

    pub fn open_default() -> EventResult<Self> {
        let path = DatabaseConnectionPool::default_runtime_path()?;
        Self::open(path)
    }

    pub fn emit_event(
        &self,
        task_id: Option<&str>,
        event_type: &str,
        payload: serde_json::Value,
    ) -> EventResult<Uuid> {
        let connection = self.connection.connection()?;
        self.emit_event_with_connection(&connection, task_id, event_type, payload)
    }

    pub fn emit_event_with_connection(
        &self,
        connection: &Connection,
        task_id: Option<&str>,
        event_type: &str,
        payload: serde_json::Value,
    ) -> EventResult<Uuid> {
        let event_id = Uuid::new_v4();
        let created_at = chrono::Utc::now().to_rfc3339();
        let payload_json = serde_json::to_string(&payload)?;
        let task_id = task_id.map(str::to_owned);

        connection.execute(
            "INSERT INTO events (event_id, task_id, event_type, payload, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![event_id.to_string(), task_id, event_type, payload_json, created_at],
        )?;

        Ok(event_id)
    }

    pub fn get_event(&self, event_id: &str) -> EventResult<Option<Event>> {
        let connection = self.connection.connection()?;
        let row = connection
            .query_row(
                "SELECT event_id, task_id, event_type, payload, created_at FROM events WHERE event_id = ?1",
                [event_id],
                |row| {
                    Ok((
                        row.get("event_id")?,
                        row.get("task_id")?,
                        row.get("event_type")?,
                        row.get::<_, String>("payload")?,
                        row.get("created_at")?,
                    ))
                },
            )
            .optional()?;

        let Some((event_id, task_id, event_type, payload, created_at)) = row else {
            return Ok(None);
        };

        let payload = serde_json::from_str::<HashMap<String, serde_json::Value>>(&payload)
            .map_err(EventError::Serialization)?;

        Ok(Some(Event {
            event_id,
            task_id,
            event_type,
            payload,
            created_at,
        }))
    }

    pub fn get_events_for_task(&self, task_id: &str) -> EventResult<Vec<Event>> {
        let connection = self.connection.connection()?;
        let mut statement = connection.prepare(
            "SELECT event_id, task_id, event_type, payload, created_at FROM events WHERE task_id = ?1 ORDER BY created_at ASC",
        )?;

        let rows = statement.query_map([task_id], |row| {
            Ok((
                row.get("event_id")?,
                row.get("task_id")?,
                row.get("event_type")?,
                row.get::<_, String>("payload")?,
                row.get("created_at")?,
            ))
        })?;

        let mut events = Vec::new();
        for row in rows {
            let (event_id, task_id, event_type, payload, created_at) = row?;
            let payload = serde_json::from_str::<HashMap<String, serde_json::Value>>(&payload)
                .map_err(EventError::Serialization)?;

            events.push(Event {
                event_id,
                task_id,
                event_type,
                payload,
                created_at,
            });
        }

        Ok(events)
    }
}

// Persona related events
pub const PERSONA_EXPRESSION_CHANGED: &str = "PersonaExpressionChanged";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpressionChangedPayload {
    pub persona_id: String,
    pub old_expression: String,
    pub new_expression: String,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn emit_event_persists_and_reads_event_by_task_id() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-events-{unique}"));
        let path = dir.join("runtime_state.db");
        let bus = EventBus::open(&path).unwrap();
        let mut payload = HashMap::new();
        payload.insert(
            "state".to_string(),
            serde_json::Value::String("Created".to_string()),
        );

        let event_id = bus
            .emit_event(
                Some("task-123"),
                "TaskCreated",
                serde_json::Value::Object(serde_json::Map::from_iter([(
                    "state".to_string(),
                    serde_json::Value::String("Created".to_string()),
                )])),
            )
            .unwrap();
        let task_events = bus.get_events_for_task("task-123").unwrap();
        let persisted = bus.get_event(&event_id.to_string()).unwrap().unwrap();

        assert_eq!(task_events.len(), 1);
        assert_eq!(persisted.task_id, "task-123");
        assert_eq!(persisted.event_type, "TaskCreated");
        assert_eq!(
            persisted.payload.get("state"),
            Some(&serde_json::Value::String("Created".to_string()))
        );

        fs::remove_dir_all(dir).unwrap();
    }
}
