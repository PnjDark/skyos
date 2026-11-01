use std::path::Path;

use rusqlite::OptionalExtension;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    events::{EventBus, EventError},
    persistence::{
        db::{DatabaseConnectionPool, DatabaseError},
        migrations::M2_TASKS_SCHEMA,
    },
    tasks::state::{InvalidTaskTransition, TaskState},
};

#[derive(Debug, Error)]
pub enum TaskStoreError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("event error: {0}")]
    Event(#[from] EventError),
    #[error("invalid task state in database: {0}")]
    InvalidState(String),
    #[error("task transition rejected: {0:?}")]
    InvalidTransition(InvalidTaskTransition),
    #[error("current task state does not match the expected state")]
    StateMismatch,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub task_id: Uuid,
    pub title: String,
    pub state: TaskState,
    pub priority: i64,
    pub retry_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct TaskStore {
    connection: DatabaseConnectionPool,
    event_bus: EventBus,
}

impl TaskStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TaskStoreError> {
        let connection = DatabaseConnectionPool::open(&path)?;
        let sqlite = connection.connection()?;
        sqlite.execute_batch(M2_TASKS_SCHEMA)?;
        let event_bus = EventBus::open(path)?;

        Ok(Self {
            connection,
            event_bus,
        })
    }

    pub fn database_path(&self) -> &Path {
        self.connection.path()
    }

    pub fn create_task(
        &self,
        title: &str,
        state: TaskState,
        priority: i64,
    ) -> Result<Uuid, TaskStoreError> {
        let task_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();
        let connection = self.connection.connection()?;

        connection.execute(
            "INSERT INTO tasks (task_id, title, state, priority, retry_count, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
            rusqlite::params![
                task_id.to_string(),
                title,
                state.as_str(),
                priority,
                now,
                now,
            ],
        )?;

        Ok(task_id)
    }

    pub fn get_task(&self, task_id: &Uuid) -> Result<Option<Task>, TaskStoreError> {
        let connection = self.connection.connection()?;
        let row = connection
            .query_row(
                "SELECT task_id, title, state, priority, retry_count, created_at, updated_at FROM tasks WHERE task_id = ?1",
                [task_id.to_string()],
                |row| {
                    let state: String = row.get("state")?;
                    let state = TaskState::try_from(state.as_str()).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(TaskStoreError::InvalidState(state.clone())),
                        )
                    })?;

                    Ok(Task {
                        task_id: Uuid::parse_str(&row.get::<_, String>("task_id")?).unwrap(),
                        title: row.get("title")?,
                        state,
                        priority: row.get("priority")?,
                        retry_count: row.get("retry_count")?,
                        created_at: row.get("created_at")?,
                        updated_at: row.get("updated_at")?,
                    })
                },
            )
            .optional()?;

        Ok(row)
    }

    pub fn transition_state(
        &self,
        task_id: Uuid,
        from_state: TaskState,
        to_state: TaskState,
    ) -> Result<Uuid, TaskStoreError> {
        let mut connection = self.connection.connection()?;
        let transaction = connection.transaction()?;
        let event_id =
            self.transition_state_with_connection(&transaction, task_id, from_state, to_state)?;
        transaction.commit()?;
        Ok(event_id)
    }

    /// Transition a task and append its state event using a caller-owned
    /// connection. This allows task state, checkpoints, and related events to
    /// participate in one SQLite transaction.
    pub fn transition_state_with_connection(
        &self,
        connection: &rusqlite::Connection,
        task_id: Uuid,
        from_state: TaskState,
        to_state: TaskState,
    ) -> Result<Uuid, TaskStoreError> {
        let current_state: String = connection.query_row(
            "SELECT state FROM tasks WHERE task_id = ?1",
            [task_id.to_string()],
            |row| row.get("state"),
        )?;
        let current_state = TaskState::try_from(current_state.as_str())
            .map_err(|_| TaskStoreError::InvalidState(current_state))?;

        if current_state != from_state {
            return Err(TaskStoreError::StateMismatch);
        }

        let transition = current_state
            .transition_to(to_state)
            .map_err(TaskStoreError::InvalidTransition)?;
        let updated_at = chrono::Utc::now().to_rfc3339();

        connection.execute(
            "UPDATE tasks SET state = ?1, updated_at = ?2 WHERE task_id = ?3",
            rusqlite::params![transition.as_str(), updated_at, task_id.to_string()],
        )?;

        let event_id = self.event_bus.emit_event_with_connection(
            connection,
            Some(&task_id.to_string()),
            "TaskStateTransitioned",
            serde_json::json!({ "from": from_state.as_str(), "to": transition.as_str() }),
        )?;

        Ok(event_id)
    }
    /// Retrieves all tasks ordered by creation time.
    pub fn list_tasks(&self) -> Result<Vec<Task>, TaskStoreError> {
        let conn = self.connection.connection()?;
        let mut stmt = conn.prepare("SELECT task_id, title, state, priority, retry_count, created_at, updated_at FROM tasks ORDER BY created_at ASC")?;
        let task_rows = stmt.query_map([], |row| {
            let id_str: String = row.get("task_id")?;
            let title: String = row.get("title")?;
            let state_str: String = row.get("state")?;
            let state = TaskState::try_from(state_str.as_str()).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(TaskStoreError::InvalidState(state_str.clone())),
                )
            })?;
            let priority: i64 = row.get("priority")?;
            let retry_count: i64 = row.get("retry_count")?;
            let created_at: String = row.get("created_at")?;
            let updated_at: String = row.get("updated_at")?;
            Ok(Task {
                task_id: Uuid::parse_str(&id_str).unwrap(),
                title,
                state,
                priority,
                retry_count,
                created_at,
                updated_at,
            })
        })?;
        let mut tasks = Vec::new();
        for t in task_rows {
            tasks.push(t?);
        }
        Ok(tasks)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn creates_and_reads_a_task_from_sqlite() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-tasks-{unique}"));
        let path = dir.join("runtime_state.db");

        let store = TaskStore::open(&path).unwrap();
        let task_id = store
            .create_task("Test Task", TaskState::Created, 10)
            .unwrap();
        let task = store.get_task(&task_id).unwrap().unwrap();

        assert_eq!(task.title, "Test Task");
        assert_eq!(task.state, TaskState::Created);
        assert_eq!(task.retry_count, 0);
        assert_eq!(task.priority, 10);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn transitions_a_task_state_and_persists_a_transition_event() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-task-transition-{unique}"));
        let path = dir.join("runtime_state.db");

        let store = TaskStore::open(&path).unwrap();
        let task_id = store
            .create_task("Transition Task", TaskState::Created, 10)
            .unwrap();

        let event_id = store
            .transition_state(task_id, TaskState::Created, TaskState::Ready)
            .unwrap();
        let task = store.get_task(&task_id).unwrap().unwrap();
        let events = store
            .event_bus
            .get_events_for_task(&task_id.to_string())
            .unwrap();
        let transition = events
            .iter()
            .find(|event| event.event_type == "TaskStateTransitioned")
            .unwrap();

        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(event_id, Uuid::parse_str(&transition.event_id).unwrap());
        assert_eq!(
            transition.payload.get("from"),
            Some(&serde_json::Value::String("Created".to_string()))
        );
        assert_eq!(
            transition.payload.get("to"),
            Some(&serde_json::Value::String("Ready".to_string()))
        );

        fs::remove_dir_all(dir).unwrap();
    }
}
