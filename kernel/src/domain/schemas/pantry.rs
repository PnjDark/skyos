use crate::domain::DomainSchema;

pub struct PantrySchema;

impl DomainSchema for PantrySchema {
    fn namespace(&self) -> &'static str {
        "pantry"
    }

    fn migrations(&self) -> &'static [&'static str] {
        &[
            "CREATE TABLE IF NOT EXISTS pantry__items (
                item_id      TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                category     TEXT NOT NULL,
                unit         TEXT NOT NULL,
                quantity     REAL NOT NULL DEFAULT 0,
                updated_at   TEXT NOT NULL
            );",
            "CREATE TABLE IF NOT EXISTS pantry__prices (
                price_id     TEXT PRIMARY KEY,
                item_id      TEXT NOT NULL REFERENCES pantry__items(item_id) ON DELETE CASCADE,
                market       TEXT NOT NULL,
                price_xaf    REAL NOT NULL,
                recorded_at  TEXT NOT NULL
            );",
            "CREATE INDEX IF NOT EXISTS idx_pantry_prices_item ON pantry__prices(item_id);",
        ]
    }
}
