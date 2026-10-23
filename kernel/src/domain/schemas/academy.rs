use crate::domain::DomainSchema;

pub struct AcademySchema;

impl DomainSchema for AcademySchema {
    fn namespace(&self) -> &'static str {
        "academy"
    }

    fn migrations(&self) -> &'static [&'static str] {
        &[
            "CREATE TABLE IF NOT EXISTS academy__sessions (
                session_id   TEXT PRIMARY KEY,
                task_id      TEXT NOT NULL,
                topic        TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                ended_at     TEXT
            );",
            "CREATE TABLE IF NOT EXISTS academy__exchanges (
                exchange_id  TEXT PRIMARY KEY,
                session_id   TEXT NOT NULL REFERENCES academy__sessions(session_id) ON DELETE CASCADE,
                role         TEXT NOT NULL CHECK(role IN ('prompt','response','evaluation')),
                content      TEXT NOT NULL,
                score        REAL,
                created_at   TEXT NOT NULL
            );",
            "CREATE INDEX IF NOT EXISTS idx_academy_exchanges_session ON academy__exchanges(session_id);",
        ]
    }
}
