use crate::domain::DomainSchema;

/// Covers Sky-Tasks, Sky-Projects, and Sky-Vault metadata.
pub struct ProductivitySchema;

impl DomainSchema for ProductivitySchema {
    fn namespace(&self) -> &'static str {
        "productivity"
    }

    fn migrations(&self) -> &'static [&'static str] {
        &[
            "CREATE TABLE IF NOT EXISTS productivity__items (
                item_id      TEXT PRIMARY KEY,
                kind         TEXT NOT NULL CHECK(kind IN ('task','project','note')),
                title        TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'open',
                parent_id    TEXT REFERENCES productivity__items(item_id) ON DELETE SET NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );",
            "CREATE TABLE IF NOT EXISTS productivity__vault_entries (
                entry_id     TEXT PRIMARY KEY,
                item_id      TEXT REFERENCES productivity__items(item_id) ON DELETE CASCADE,
                artifact_id  TEXT,
                content      TEXT NOT NULL,
                tags         TEXT,
                created_at   TEXT NOT NULL
            );",
            "CREATE INDEX IF NOT EXISTS idx_productivity_items_kind ON productivity__items(kind);",
            "CREATE INDEX IF NOT EXISTS idx_productivity_vault_item ON productivity__vault_entries(item_id);",
        ]
    }
}
