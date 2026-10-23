// TaskCategory enum for distinguishing system vs user tasks
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskCategory {
    UserInstruction,       // Manual user task
    SoftwareEngineering,   // SDLC Council / CoderAgent tasks
    NightlyPacing,         // Sky-Pacing retrospective audit
    MediaGeneration,       // SVG / VideoStudio render pipeline
    SelfUpdate,            // Sky editing her own assets
}
