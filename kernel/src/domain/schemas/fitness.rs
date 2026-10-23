use crate::domain::DomainSchema;

pub struct FitnessSchema;

impl DomainSchema for FitnessSchema {
    fn namespace(&self) -> &'static str {
        "fitness"
    }

    fn migrations(&self) -> &'static [&'static str] {
        &[
            "CREATE TABLE IF NOT EXISTS fitness__workouts (
                workout_id   TEXT PRIMARY KEY,
                task_id      TEXT NOT NULL,
                performed_at TEXT NOT NULL,
                notes        TEXT
            );",
            "CREATE TABLE IF NOT EXISTS fitness__sets (
                set_id      TEXT PRIMARY KEY,
                workout_id  TEXT NOT NULL REFERENCES fitness__workouts(workout_id) ON DELETE CASCADE,
                exercise    TEXT NOT NULL,
                weight_kg   REAL NOT NULL,
                reps        INTEGER NOT NULL,
                rpe         REAL,
                created_at  TEXT NOT NULL
            );",
            "CREATE INDEX IF NOT EXISTS idx_fitness_sets_workout ON fitness__sets(workout_id);",
            "CREATE INDEX IF NOT EXISTS idx_fitness_workouts_task ON fitness__workouts(task_id);",
        ]
    }
}
