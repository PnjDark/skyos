use std::fmt;

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Created,
    Ready,
    Claimed,
    Running,
    Waiting,
    Blocked,
    /// Cancellation requested; no new work may start, budget stays held.
    /// Reached from any active state, and only leaves via `Cancelled` or
    /// `Escalated`.
    Cancelling,
    Escalated,
    Failed,
    Completed,
    /// Terminal cancellation. Reached only through `Cancelling`, once every
    /// descendant is terminal and every live execution acknowledged.
    Cancelled,
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Ready => "Ready",
            Self::Claimed => "Claimed",
            Self::Running => "Running",
            Self::Waiting => "Waiting",
            Self::Blocked => "Blocked",
            Self::Cancelling => "Cancelling",
            Self::Escalated => "Escalated",
            Self::Failed => "Failed",
            Self::Completed => "Completed",
            Self::Cancelled => "Cancelled",
        }
    }

    /// True when the task can no longer change state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Ready)
                | (Self::Created, Self::Blocked)
                | (Self::Ready, Self::Claimed)
                | (Self::Claimed, Self::Running)
                | (Self::Claimed, Self::Blocked)
                | (Self::Running, Self::Waiting)
                | (Self::Running, Self::Blocked)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::Completed)
                | (Self::Waiting, Self::Running)
                | (Self::Waiting, Self::Blocked)
                | (Self::Blocked, Self::Ready)
                | (Self::Blocked, Self::Escalated)
                | (Self::Escalated, Self::Ready)
                | (Self::Escalated, Self::Failed)
                | (Self::Failed, Self::Ready)
                // Phase 6.1D — cancellation.
                // Any active state may enter `Cancelling`; a terminal state may
                // never be overwritten by a cancellation request.
                | (Self::Created, Self::Cancelling)
                | (Self::Ready, Self::Cancelling)
                | (Self::Claimed, Self::Cancelling)
                | (Self::Running, Self::Cancelling)
                | (Self::Waiting, Self::Cancelling)
                | (Self::Blocked, Self::Cancelling)
                | (Self::Escalated, Self::Cancelling)
                // Terminal cancellation is reachable only through `Cancelling`,
                // and only once the cascade is confirmed. There is deliberately
                // no edge from any other state, and none into `Completed`.
                | (Self::Cancelling, Self::Cancelled)
                | (Self::Cancelling, Self::Escalated)
        )
    }

    pub fn transition_to(self, next: Self) -> Result<Self, InvalidTaskTransition> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(InvalidTaskTransition::new(self, next))
        }
    }
}

impl TryFrom<&str> for TaskState {
    type Error = TaskStateError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Created" => Ok(Self::Created),
            "Ready" => Ok(Self::Ready),
            "Claimed" => Ok(Self::Claimed),
            "Running" => Ok(Self::Running),
            "Waiting" => Ok(Self::Waiting),
            "Blocked" => Ok(Self::Blocked),
            "Cancelling" => Ok(Self::Cancelling),
            "Escalated" => Ok(Self::Escalated),
            "Failed" => Ok(Self::Failed),
            "Completed" => Ok(Self::Completed),
            "Cancelled" => Ok(Self::Cancelled),
            _ => Err(TaskStateError::UnknownState(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStateError {
    UnknownState(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTaskTransition {
    pub from: TaskState,
    pub to: TaskState,
}

impl InvalidTaskTransition {
    fn new(from: TaskState, to: TaskState) -> Self {
        Self { from, to }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEvent {
    pub event_id: Uuid,
    pub task_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
}

pub fn rebuild_task_state(events: &[HistoryEvent]) -> Option<TaskState> {
    events.iter().fold(None, |current_state, event| {
        match event.event_type.as_str() {
            "TaskCreated" => Some(TaskState::Created),
            "TaskStarted" => Some(TaskState::Running),
            "TaskWaiting" => Some(TaskState::Waiting),
            "TaskCompleted" => Some(TaskState::Completed),
            "TaskFailed" => Some(TaskState::Failed),
            _ => current_state,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_round_trips_through_string() {
        assert_eq!(TaskState::Created.to_string(), "Created");
        assert_eq!(TaskState::try_from("Created"), Ok(TaskState::Created));
        assert!(TaskState::try_from("Unknown").is_err());
    }

    #[test]
    fn valid_transition_is_allowed() {
        assert_eq!(
            TaskState::Created.transition_to(TaskState::Ready),
            Ok(TaskState::Ready)
        );
    }

    #[test]
    fn invalid_transition_is_rejected() {
        assert_eq!(
            TaskState::Created.transition_to(TaskState::Completed),
            Err(InvalidTaskTransition::new(
                TaskState::Created,
                TaskState::Completed
            ))
        );
    }

    #[test]
    fn reconstructs_completed_state_from_event_history() {
        let task_id = Uuid::new_v4();
        let events = vec![
            HistoryEvent {
                event_id: Uuid::new_v4(),
                task_id,
                event_type: "TaskCreated".into(),
                payload: serde_json::json!({}),
            },
            HistoryEvent {
                event_id: Uuid::new_v4(),
                task_id,
                event_type: "TaskStarted".into(),
                payload: serde_json::json!({}),
            },
            HistoryEvent {
                event_id: Uuid::new_v4(),
                task_id,
                event_type: "ToolCalled".into(),
                payload: serde_json::json!({"tool": "fs.read"}),
            },
            HistoryEvent {
                event_id: Uuid::new_v4(),
                task_id,
                event_type: "ToolCompleted".into(),
                payload: serde_json::json!({}),
            },
            HistoryEvent {
                event_id: Uuid::new_v4(),
                task_id,
                event_type: "TaskCompleted".into(),
                payload: serde_json::json!({}),
            },
        ];

        assert_eq!(rebuild_task_state(&events), Some(TaskState::Completed));
    }
}
