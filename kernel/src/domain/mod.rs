use crate::persistence::db::{DatabaseConnectionPool, DatabaseError};
use thiserror::Error;

pub mod schemas;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("domain namespace '{0}' contains invalid characters")]
    InvalidNamespace(String),
    #[error("query error in domain '{namespace}': {cause}")]
    QueryFailed { namespace: String, cause: String },
}

pub type DomainResult<T> = Result<T, DomainError>;

/// A domain schema registers its namespace and SQL migrations with the kernel.
///
/// Each namespace is an isolated logical partition within the shared SQLite
/// database.  Table names are prefixed with `<namespace>__` so schemas from
/// different domains never collide.
pub trait DomainSchema {
    /// Short ASCII identifier, e.g. `"fitness"`, `"pantry"`, `"finance"`.
    /// Must contain only `[a-z0-9_]`.
    fn namespace(&self) -> &'static str;

    /// Ordered list of idempotent `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX
    /// IF NOT EXISTS` statements.  Each statement is applied once inside a
    /// single WAL transaction.
    fn migrations(&self) -> &'static [&'static str];
}

/// Validates that a namespace string is safe to embed in SQL identifiers.
fn validate_namespace(ns: &str) -> DomainResult<()> {
    if ns.is_empty()
        || !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(DomainError::InvalidNamespace(ns.to_string()));
    }
    Ok(())
}

/// Kernel-owned store that applies domain schema migrations and executes
/// capability-gated queries against the shared WAL database.
pub struct DomainStore {
    pool: DatabaseConnectionPool,
}

impl DomainStore {
    pub fn open(pool: DatabaseConnectionPool) -> Self {
        Self { pool }
    }

    /// Apply a domain's migrations idempotently inside a WAL transaction.
    ///
    /// Safe to call on every startup — all statements use `IF NOT EXISTS`.
    pub fn register_domain<S: DomainSchema>(&self, schema: &S) -> DomainResult<()> {
        validate_namespace(schema.namespace())?;
        let conn = self.pool.connection()?;
        conn.execute_batch("BEGIN;")?;
        for sql in schema.migrations() {
            conn.execute_batch(sql)?;
        }
        conn.execute_batch("COMMIT;")?;
        Ok(())
    }

    /// Execute a read-only parameterized query against a registered domain.
    ///
    /// The SQLite authorizer callback enforces table-level namespace isolation:
    /// any table access outside `<namespace>__*`, any mutation attempt (including
    /// CTE writes), and any access to system tables or PRAGMAs is strictly DENIED
    /// by SQLite's query compiler.
    pub fn query(
        &self,
        namespace: &str,
        sql: &str,
        params: &[serde_json::Value],
    ) -> DomainResult<Vec<serde_json::Value>> {
        validate_namespace(namespace)?;
        if !sql.trim_start().to_ascii_uppercase().starts_with("SELECT") {
            return Err(DomainError::QueryFailed {
                namespace: namespace.to_string(),
                cause: "Only SELECT statements are permitted in query()".to_string(),
            });
        }
        let conn = self.pool.connection()?;
        let prefix = format!("{namespace}__");
        conn.authorizer(Some(move |ctx: rusqlite::hooks::AuthContext| {
            match ctx.action {
                rusqlite::hooks::AuthAction::Read { table_name, .. } => {
                    if table_name.starts_with(&prefix) {
                        rusqlite::hooks::Authorization::Allow
                    } else {
                        rusqlite::hooks::Authorization::Deny
                    }
                }
                rusqlite::hooks::AuthAction::Select
                | rusqlite::hooks::AuthAction::Function { .. }
                | rusqlite::hooks::AuthAction::Recursive => rusqlite::hooks::Authorization::Allow,
                _ => rusqlite::hooks::Authorization::Deny,
            }
        }));

        let mut stmt = conn.prepare(sql).map_err(|e| DomainError::QueryFailed {
            namespace: namespace.to_string(),
            cause: e.to_string(),
        })?;

        let col_count = stmt.column_count();
        let col_names: Vec<String> = (0..col_count)
            .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
            .collect();

        let bound_params: Vec<rusqlite::types::Value> = params.iter().map(json_to_sql).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bound_params.iter()), |row| {
                let mut obj = serde_json::Map::new();
                for (i, name) in col_names.iter().enumerate() {
                    let val: rusqlite::types::Value = row.get(i)?;
                    obj.insert(name.clone(), sql_to_json(val));
                }
                Ok(serde_json::Value::Object(obj))
            })
            .map_err(|e| DomainError::QueryFailed {
                namespace: namespace.to_string(),
                cause: e.to_string(),
            })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| DomainError::QueryFailed {
                namespace: namespace.to_string(),
                cause: e.to_string(),
            })?);
        }
        Ok(results)
    }

    /// Execute a mutating statement (`INSERT`, `UPDATE`, `DELETE`) inside a
    /// WAL transaction with strict authorizer validation.
    ///
    /// The SQLite authorizer callback guarantees that mutations can ONLY affect
    /// tables matching the authorized `<namespace>__*` prefix. Any mutation targeting
    /// another namespace's tables, system tables, DDL operations, or PRAGMAs is
    /// rejected by the SQLite engine, and the transaction is automatically rolled back.
    pub fn mutate(
        &self,
        namespace: &str,
        sql: &str,
        params: &[serde_json::Value],
    ) -> DomainResult<usize> {
        validate_namespace(namespace)?;
        let upper = sql.trim_start().to_ascii_uppercase();
        if upper.starts_with("SELECT") {
            return Err(DomainError::QueryFailed {
                namespace: namespace.to_string(),
                cause: "SELECT is not permitted in mutate(); use query() instead".to_string(),
            });
        }
        let mut conn = self.pool.connection()?;
        let prefix = format!("{namespace}__");
        let ns = namespace.to_string();
        conn.authorizer(Some(move |ctx: rusqlite::hooks::AuthContext| {
            match ctx.action {
                rusqlite::hooks::AuthAction::Insert { table_name }
                | rusqlite::hooks::AuthAction::Update { table_name, .. }
                | rusqlite::hooks::AuthAction::Delete { table_name } => {
                    if table_name.starts_with(&prefix) {
                        rusqlite::hooks::Authorization::Allow
                    } else {
                        rusqlite::hooks::Authorization::Deny
                    }
                }
                rusqlite::hooks::AuthAction::Read { table_name, .. } => {
                    if table_name.starts_with(&prefix) {
                        rusqlite::hooks::Authorization::Allow
                    } else {
                        rusqlite::hooks::Authorization::Deny
                    }
                }
                rusqlite::hooks::AuthAction::Select
                | rusqlite::hooks::AuthAction::Function { .. }
                | rusqlite::hooks::AuthAction::Recursive => rusqlite::hooks::Authorization::Allow,
                rusqlite::hooks::AuthAction::Transaction { .. } => {
                    rusqlite::hooks::Authorization::Allow
                }
                _ => rusqlite::hooks::Authorization::Deny,
            }
        }));

        let bound_params: Vec<rusqlite::types::Value> = params.iter().map(json_to_sql).collect();
        let tx = conn.transaction().map_err(|e| DomainError::QueryFailed {
            namespace: ns.clone(),
            cause: format!("Failed to begin transaction: {e}"),
        })?;
        let affected = tx
            .execute(sql, rusqlite::params_from_iter(bound_params.iter()))
            .map_err(|e| DomainError::QueryFailed {
                namespace: ns.clone(),
                cause: e.to_string(),
            })?;
        tx.commit().map_err(|e| DomainError::QueryFailed {
            namespace: ns,
            cause: format!("Failed to commit transaction: {e}"),
        })?;
        Ok(affected)
    }
}

// ── type conversion helpers ───────────────────────────────────────────────────

fn json_to_sql(v: &serde_json::Value) -> rusqlite::types::Value {
    match v {
        serde_json::Value::Null => rusqlite::types::Value::Null,
        serde_json::Value::Bool(b) => rusqlite::types::Value::Integer(*b as i64),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rusqlite::types::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                rusqlite::types::Value::Real(f)
            } else {
                rusqlite::types::Value::Null
            }
        }
        serde_json::Value::String(s) => rusqlite::types::Value::Text(s.clone()),
        other => rusqlite::types::Value::Text(other.to_string()),
    }
}

fn sql_to_json(v: rusqlite::types::Value) -> serde_json::Value {
    match v {
        rusqlite::types::Value::Null => serde_json::Value::Null,
        rusqlite::types::Value::Integer(i) => serde_json::json!(i),
        rusqlite::types::Value::Real(f) => serde_json::json!(f),
        rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
        rusqlite::types::Value::Blob(b) => serde_json::Value::String(hex::encode(b)),
    }
}
