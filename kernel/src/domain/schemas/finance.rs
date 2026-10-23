use crate::domain::DomainSchema;

pub struct FinanceSchema;

impl DomainSchema for FinanceSchema {
    fn namespace(&self) -> &'static str {
        "finance"
    }

    fn migrations(&self) -> &'static [&'static str] {
        &[
            "CREATE TABLE IF NOT EXISTS finance__ledger (
                entry_id     TEXT PRIMARY KEY,
                task_id      TEXT NOT NULL,
                amount       REAL NOT NULL,
                currency     TEXT NOT NULL,
                rail         TEXT NOT NULL,
                direction    TEXT NOT NULL CHECK(direction IN ('debit','credit')),
                description  TEXT,
                occurred_at  TEXT NOT NULL
            );",
            "CREATE TABLE IF NOT EXISTS finance__envelopes (
                envelope_id  TEXT PRIMARY KEY,
                name         TEXT NOT NULL UNIQUE,
                budget       REAL NOT NULL,
                currency     TEXT NOT NULL
            );",
            "CREATE INDEX IF NOT EXISTS idx_finance_ledger_task ON finance__ledger(task_id);",
            "CREATE INDEX IF NOT EXISTS idx_finance_ledger_rail ON finance__ledger(rail);",
        ]
    }
}
