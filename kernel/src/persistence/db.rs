use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, Result};
use thiserror::Error;

pub const DEFAULT_RUNTIME_STATE_PATH: &str = ".sky/runtime_state.db";

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("failed to create runtime database directory: {0}")]
    CreateDirectory(std::io::Error),
    #[error("failed to initialize SQLite database: {0}")]
    Connection(#[from] rusqlite::Error),
}

#[derive(Debug, Clone)]
pub struct DatabaseConnectionPool {
    path: PathBuf,
}

impl DatabaseConnectionPool {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(DatabaseError::CreateDirectory)?;
        }

        let connection = Connection::open(path)?;
        connection
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .map_err(DatabaseError::Connection)?;

        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn default_runtime_path() -> Result<PathBuf, DatabaseError> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| DatabaseError::CreateDirectory(std::io::Error::other("HOME not set")))?;
        Ok(PathBuf::from(home).join(DEFAULT_RUNTIME_STATE_PATH))
    }

    pub fn connection(&self) -> Result<Connection, DatabaseError> {
        let connection = Connection::open(&self.path)?;
        connection
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .map_err(DatabaseError::Connection)?;

        Ok(connection)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn database_connection_creates_runtime_state_and_enables_sqlite_pragmas() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-kernel-{unique}"));
        let path = dir.join("runtime_state.db");

        let connection = DatabaseConnectionPool::open(&path).unwrap();

        let journal_mode: String = connection
            .connection()
            .unwrap()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let foreign_keys: i32 = connection
            .connection()
            .unwrap()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();

        assert_eq!(journal_mode, "wal");
        assert_eq!(foreign_keys, 1);

        fs::remove_dir_all(dir).unwrap();
    }
}
