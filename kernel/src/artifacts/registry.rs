use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    File,
    Directory,
    Log,
    Diff,
    Binary,
    Snapshot, // Bounded operation snapshot artifact
    // Added for Asset Engine & Persona Self-Updates
    SvgVector,       // Raw or parametric SVG graphic
    LottieAnimation, // JSON skeletal animation spec
    AudioTrack,      // Synthesized audio / focus track (.wav, .m3u)
    RenderedVideo,   // Web-to-Video render (.mp4, .webm)
    BrandTokenPatch, // Color/typography token payload (~/SkyVault/Brands/)
}

impl ArtifactType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Log => "log",
            Self::Diff => "diff",
            Self::Binary => "binary",
            Self::Snapshot => "snapshot",
            Self::SvgVector => "svg_vector",
            Self::LottieAnimation => "lottie_animation",
            Self::AudioTrack => "audio_track",
            Self::RenderedVideo => "rendered_video",
            Self::BrandTokenPatch => "brand_token_patch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub task_id: Option<String>,
    pub artifact_type: ArtifactType,
    pub hash: String,
    pub size_bytes: u64,
    pub location_uri: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("database error: {0}")]
    Database(String),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid artifact state: {0}")]
    InvalidArtifact(String),
    #[error("artifact not found: {0}")]
    NotFound(String),
    #[error("artifact hash is invalid: {0}")]
    InvalidHash(String),
    #[error("artifact parent does not exist: {0}")]
    ParentNotFound(String),
}

pub struct ArtifactRegistry {
    connection: rusqlite::Connection,
    store_root: PathBuf,
}

impl ArtifactRegistry {
    pub fn open(
        path: impl AsRef<Path>,
        store_root: impl AsRef<Path>,
    ) -> Result<Self, ArtifactError> {
        let connection = rusqlite::Connection::open(path)?;
        // busy_timeout: WAL allows only one writer at a time; without a
        // timeout, concurrent writers fail immediately with SQLITE_BUSY
        // instead of briefly queueing.
        connection.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
        )?;
        connection.execute_batch(crate::persistence::migrations::M3_ARTIFACTS_SCHEMA)?;

        let store_root = store_root.as_ref().to_path_buf();
        fs::create_dir_all(store_root.join("sha256"))?;

        Ok(Self {
            connection,
            store_root,
        })
    }

    /// Register an in-memory text payload (e.g. a commit hash or diff output) as a CAS artifact.
    pub fn register_text_artifact(
        &mut self,
        content: &str,
        task_id: &str,
        artifact_type: ArtifactType,
        parent_id: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<Artifact, ArtifactError> {
        let source_bytes = content.as_bytes();
        let hash = hex::encode(Sha256::digest(source_bytes));
        let stored_path = self.store_root.join("sha256").join(&hash);

        if let Some(pid) = parent_id {
            self.get_artifact(pid)?
                .ok_or_else(|| ArtifactError::ParentNotFound(pid.to_string()))?;
        }

        let artifact_id = hash.clone();
        let size_bytes = source_bytes.len() as u64;
        let location_uri = Self::path_to_file_uri(&stored_path);
        let metadata_map = serde_json::from_value::<HashMap<String, serde_json::Value>>(metadata)?;
        let created_at = chrono::Utc::now().to_rfc3339();

        // IMMEDIATE: acquire the write lock up front. A deferred transaction
        // that reads first and then writes can fail with an immediate
        // SQLITE_BUSY (snapshot upgrade) that busy_timeout cannot retry.
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<Artifact> = transaction
            .query_row(
                "SELECT artifact_id, task_id, artifact_type, hash, size_bytes, location_uri, metadata FROM artifacts WHERE hash = ?1",
                [&hash],
                |row| {
                    let artifact_type: String = row.get("artifact_type")?;
                    let artifact_type =
                        ArtifactType::try_from(artifact_type.as_str()).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                    let metadata: String = row.get("metadata")?;
                    let metadata = serde_json::from_str::<HashMap<String, serde_json::Value>>(
                        &metadata,
                    )
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(Artifact {
                        artifact_id: row.get("artifact_id")?,
                        task_id: row.get("task_id")?,
                        artifact_type,
                        hash: row.get("hash")?,
                        size_bytes: row.get("size_bytes")?,
                        location_uri: row.get("location_uri")?,
                        metadata,
                    })
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return Ok(existing);
        }

        if !stored_path.exists() {
            fs::create_dir_all(stored_path.parent().unwrap())?;
            fs::write(&stored_path, source_bytes)?;
        }

        transaction.execute(
            "INSERT INTO artifacts (artifact_id, task_id, artifact_type, hash, size_bytes, location_uri, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                artifact_id,
                task_id,
                artifact_type.as_str(),
                hash,
                size_bytes,
                location_uri,
                serde_json::to_string(&metadata_map)?,
                created_at,
            ],
        )?;

        if let Some(pid) = parent_id {
            transaction.execute(
                "INSERT INTO artifact_lineage (child_id, parent_id) VALUES (?1, ?2)",
                rusqlite::params![artifact_id, pid],
            )?;
        }

        transaction.commit()?;

        Ok(Artifact {
            artifact_id,
            task_id: Some(task_id.to_owned()),
            artifact_type,
            hash,
            size_bytes,
            location_uri,
            metadata: metadata_map,
        })
    }

    pub fn register_file_artifact(
        &mut self,
        source_path: impl AsRef<Path>,
        task_id: Option<&str>,
        artifact_type: ArtifactType,
        parent_id: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<Artifact, ArtifactError> {
        let source_path = source_path.as_ref();
        let source_bytes = fs::read(source_path)?;
        let hash = hex::encode(Sha256::digest(&source_bytes));
        let stored_path = self.store_root.join("sha256").join(&hash);

        if let Some(parent_id) = parent_id {
            self.get_artifact(parent_id)?
                .ok_or_else(|| ArtifactError::ParentNotFound(parent_id.to_string()))?;
        }

        let artifact_id = hash.clone();
        let size_bytes = source_bytes.len() as u64;
        let location_uri = Self::path_to_file_uri(&stored_path);
        let metadata = serde_json::from_value::<HashMap<String, serde_json::Value>>(metadata)?;
        let created_at = chrono::Utc::now().to_rfc3339();

        eprintln!(
            "debug artifact path: source={} store_root={} stored={} uri={}",
            source_path.display(),
            self.store_root.display(),
            stored_path.display(),
            location_uri
        ); // See register_text_artifact: IMMEDIATE avoids non-retryable
        // SQLITE_BUSY on read→write upgrade under concurrent registration.
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<Artifact> = transaction
            .query_row(
                "SELECT artifact_id, task_id, artifact_type, hash, size_bytes, location_uri, metadata FROM artifacts WHERE hash = ?1",
                [&hash],
                |row| {
                    let artifact_type: String = row.get("artifact_type")?;
                    let artifact_type =
                        ArtifactType::try_from(artifact_type.as_str()).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    let metadata: String = row.get("metadata")?;
                    let metadata = serde_json::from_str::<HashMap<String, serde_json::Value>>(&metadata).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                    Ok(Artifact {
                        artifact_id: row.get("artifact_id")?,
                        task_id: row.get("task_id")?,
                        artifact_type,
                        hash: row.get("hash")?,
                        size_bytes: row.get("size_bytes")?,
                        location_uri: row.get("location_uri")?,
                        metadata,
                    })
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return Ok(existing);
        }

        if !stored_path.exists() {
            fs::create_dir_all(stored_path.parent().unwrap())?;
            fs::write(&stored_path, &source_bytes)?;
        }

        transaction.execute(
            "INSERT INTO artifacts (artifact_id, task_id, artifact_type, hash, size_bytes, location_uri, metadata, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                artifact_id,
                task_id,
                artifact_type.as_str(),
                hash,
                size_bytes,
                location_uri,
                serde_json::to_string(&metadata)?,
                created_at,
            ],
        )?;

        if let Some(parent_id) = parent_id {
            transaction.execute(
                "INSERT INTO artifact_lineage (child_id, parent_id) VALUES (?1, ?2)",
                rusqlite::params![artifact_id, parent_id],
            )?;
        }

        transaction.commit()?;

        Ok(Artifact {
            artifact_id,
            task_id: task_id.map(str::to_owned),
            artifact_type,
            hash,
            size_bytes,
            location_uri,
            metadata,
        })
    }

    pub fn get_artifact(&self, artifact_id: &str) -> Result<Option<Artifact>, ArtifactError> {
        let artifact = self.connection
            .query_row(
                "SELECT artifact_id, task_id, artifact_type, hash, size_bytes, location_uri, metadata FROM artifacts WHERE artifact_id = ?1",
                [artifact_id],
                |row| -> rusqlite::Result<Artifact> {
                    let metadata: String = row.get("metadata")?;
                    let metadata = serde_json::from_str::<HashMap<String, serde_json::Value>>(&metadata)
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    let artifact_type: String = row.get("artifact_type")?;
                    let artifact_type = ArtifactType::try_from(artifact_type.as_str())
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;

                    Ok(Artifact {
                        artifact_id: row.get("artifact_id")?,
                        task_id: row.get("task_id")?,
                        artifact_type,
                        hash: row.get("hash")?,
                        size_bytes: row.get("size_bytes")?,
                        location_uri: row.get("location_uri")?,
                        metadata,
                    })
                },
            )
            .optional()?;

        Ok(artifact)
    }

    pub fn get_artifacts_for_task(&self, task_id: &str) -> Result<Vec<Artifact>, ArtifactError> {
        let mut statement = self.connection.prepare(
            "SELECT artifact_id, task_id, artifact_type, hash, size_bytes, location_uri, metadata
             FROM artifacts WHERE task_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = statement.query_map([task_id], |row| {
            let artifact_type: String = row.get("artifact_type")?;
            let artifact_type =
                ArtifactType::try_from(artifact_type.as_str()).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            let metadata: String = row.get("metadata")?;
            let metadata = serde_json::from_str::<HashMap<String, serde_json::Value>>(&metadata)
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;

            Ok(Artifact {
                artifact_id: row.get("artifact_id")?,
                task_id: row.get("task_id")?,
                artifact_type,
                hash: row.get("hash")?,
                size_bytes: row.get("size_bytes")?,
                location_uri: row.get("location_uri")?,
                metadata,
            })
        })?;

        rows.map(|row| row.map_err(ArtifactError::from))
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn get_artifact_by_hash(&self, hash: &str) -> Result<Option<Artifact>, ArtifactError> {
        let artifact_id: String = self
            .connection
            .query_row(
                "SELECT artifact_id FROM artifacts WHERE hash = ?1",
                [hash],
                |row| row.get("artifact_id"),
            )
            .optional()?
            .unwrap_or_default();

        if artifact_id.is_empty() {
            Ok(None)
        } else {
            self.get_artifact(&artifact_id)
        }
    }

    pub fn get_lineage_chain(&self, artifact_id: &str) -> Result<Vec<String>, ArtifactError> {
        let mut rows = self.connection.prepare(
            "WITH RECURSIVE lineage(artifact_id, depth) AS (
                SELECT ?1, 0
                UNION ALL
                SELECT artifact_lineage.parent_id, lineage.depth + 1
                FROM artifact_lineage
                JOIN lineage ON artifact_lineage.child_id = lineage.artifact_id
            )
            SELECT artifact_id FROM lineage ORDER BY depth ASC",
        )?;

        let chain = rows.query_map([artifact_id], |row| row.get("artifact_id"))?;
        chain
            .map(|row| row.map_err(ArtifactError::from))
            .collect::<Result<Vec<_>, _>>()
    }

    fn path_to_file_uri(path: &Path) -> String {
        let path = path.to_string_lossy().replace('\\', "/");
        format!("file://{}", path)
    }

    #[allow(dead_code)]
    fn file_uri_to_path(uri: &str) -> PathBuf {
        let path = uri.trim_start_matches("file://");
        PathBuf::from(path)
    }
}

impl TryFrom<&str> for ArtifactType {
    type Error = ArtifactError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "file" => Ok(Self::File),
            "directory" => Ok(Self::Directory),
            "log" => Ok(Self::Log),
            "diff" => Ok(Self::Diff),
            "binary" => Ok(Self::Binary),
            "snapshot" => Ok(Self::Snapshot),
            "svg_vector" => Ok(Self::SvgVector),
            "lottie_animation" => Ok(Self::LottieAnimation),
            "audio_track" => Ok(Self::AudioTrack),
            "rendered_video" => Ok(Self::RenderedVideo),
            "brand_token_patch" => Ok(Self::BrandTokenPatch),
            _ => Err(ArtifactError::InvalidArtifact(value.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::*;

    #[test]
    fn registers_and_retrieves_content_addressable_artifacts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-artifacts-{unique}"));
        fs::create_dir_all(&dir).expect("Failed to create test directory");
        let database = dir.join("runtime_state.db");
        let store_root = dir.join("artifacts");
        let source = dir.join("source.txt");
        fs::write(&source, "hello from sky").unwrap();

        let mut registry = ArtifactRegistry::open(&database, &store_root).unwrap();
        // Read source bytes and compute expected hash dynamically
        let source_bytes = fs::read(&source).unwrap();
        let expected_hash = format!("{:x}", sha2::Sha256::digest(&source_bytes));

        let artifact = registry
            .register_file_artifact(
                &source,
                Some("task-1"),
                ArtifactType::File,
                None,
                json!({ "source": "day-3" }),
            )
            .unwrap();

        assert_eq!(artifact.hash, expected_hash);
        assert_eq!(artifact.artifact_id, artifact.hash);
        assert_eq!(artifact.size_bytes, source_bytes.len() as u64);
        assert!(
            registry
                .get_artifact(&artifact.artifact_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            registry
                .get_artifact_by_hash(&artifact.hash)
                .unwrap()
                .unwrap()
                .artifact_id,
            artifact.artifact_id
        );

        // Clean up: drop registry to release file handles, then delete temp directory
        drop(registry);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_duplicate_registration_and_records_lineage() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-artifact-lineage-{unique}"));
        fs::create_dir_all(&dir).expect("Failed to create test directory");
        let database = dir.join("runtime_state.db");
        let store_root = dir.join("artifacts");
        let source_a = dir.join("a.txt");
        let source_b = dir.join("b.txt");
        fs::write(&source_a, "A1").unwrap();
        fs::write(&source_b, "A2").unwrap();

        let mut registry = ArtifactRegistry::open(&database, &store_root).unwrap();
        let a1 = registry
            .register_file_artifact(
                &source_a,
                Some("task-1"),
                ArtifactType::File,
                None,
                json!({}),
            )
            .unwrap();
        let a2 = registry
            .register_file_artifact(
                &source_b,
                Some("task-2"),
                ArtifactType::File,
                Some(&a1.artifact_id),
                json!({}),
            )
            .unwrap();

        assert_eq!(a2.artifact_id, a2.hash);
        let lineage = registry.get_lineage_chain(&a2.artifact_id).unwrap();
        assert_eq!(lineage, vec![a2.artifact_id.clone(), a1.artifact_id]);
        let duplicate = registry
            .register_file_artifact(
                &source_b,
                Some("task-3"),
                ArtifactType::File,
                None,
                json!({}),
            )
            .unwrap();
        assert_eq!(duplicate.artifact_id, a2.artifact_id);

        drop(registry);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preserves_the_original_source_and_verifies_stored_bytes() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skyos-artifact-store-{unique}"));
        fs::create_dir_all(&dir).expect("Failed to create test directory");
        let database = dir.join("runtime_state.db");
        let store_root = dir.join("artifacts");
        let source = dir.join("source.txt");
        fs::write(&source, "immutable content").unwrap();

        let mut registry = ArtifactRegistry::open(&database, &store_root).unwrap();
        let artifact = registry
            .register_file_artifact(&source, Some("task-1"), ArtifactType::File, None, json!({}))
            .unwrap();
        let stored = ArtifactRegistry::file_uri_to_path(&artifact.location_uri);
        let stored_bytes = fs::read(&stored).unwrap();
        let actual = fs::read(&source).unwrap();

        assert_eq!(stored_bytes, actual);
        assert_ne!(stored, source);
        assert_eq!(stored_bytes.len() as u64, artifact.size_bytes);

        drop(registry);
        fs::remove_dir_all(dir).unwrap();
    }
}
