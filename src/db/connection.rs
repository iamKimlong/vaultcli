//! Database Connection Management
//!
//! Handles SQLite database connections and configuration.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use super::{schema::init_schema, DbResult};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database file
    pub path: PathBuf,
    /// Enable WAL mode for better concurrency
    pub wal_mode: bool,
    /// Enable foreign keys
    pub foreign_keys: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            wal_mode: true,
            foreign_keys: true,
        }
    }
}

impl DatabaseConfig {
    /// Create config for in-memory database (testing)
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::from(":memory:"),
            wal_mode: false,
            foreign_keys: true,
        }
    }

    /// Create config for a specific path
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }
}

/// Get default database path (~/.credlock/vault.db)
fn default_db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".credlock")
        .join("vault.db")
}

/// Database wrapper with connection management
pub struct Database {
    conn: Connection,
    config: DatabaseConfig,
}

impl Database {
    /// Open or create a database with the given config
    pub fn open(config: DatabaseConfig) -> DbResult<Self> {
        // Create parent directory if needed
        if let Some(parent) = config.path.parent() {
            if !parent.exists() && config.path.to_str() != Some(":memory:") {
                std::fs::create_dir_all(parent).map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(format!("Failed to create directory: {}", e)),
                    )
                })?;
            }
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;

        let conn = if config.path.to_str() == Some(":memory:") {
            Connection::open_in_memory()?
        } else {
            Connection::open_with_flags(&config.path, flags)?
        };

        // Configure connection
        if config.foreign_keys {
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        }

        if config.wal_mode && config.path.to_str() != Some(":memory:") {
            conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        }

        // Set busy timeout for concurrent access
        conn.busy_timeout(std::time::Duration::from_secs(5))?;

        // Initialize schema
        init_schema(&conn)?;

        Ok(Self { conn, config })
    }

    /// Open with default configuration
    pub fn open_default() -> DbResult<Self> {
        Self::open(DatabaseConfig::default())
    }

    /// Open in-memory database for testing
    pub fn open_in_memory() -> DbResult<Self> {
        Self::open(DatabaseConfig::in_memory())
    }

    /// Get reference to connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get mutable reference to connection
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Get database path
    pub fn path(&self) -> &Path {
        &self.config.path
    }

    /// Check if database exists at the configured path
    pub fn exists(&self) -> bool {
        if self.config.path.to_str() == Some(":memory:") {
            return true;
        }
        self.config.path.exists()
    }

    /// Vacuum the database to reclaim space
    pub fn vacuum(&self) -> DbResult<()> {
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Get database size in bytes
    pub fn size(&self) -> std::io::Result<u64> {
        if self.config.path.to_str() == Some(":memory:") {
            return Ok(0);
        }
        Ok(std::fs::metadata(&self.config.path)?.len())
    }

    /// Execute a function within a transaction
    pub fn transaction<T, F>(&mut self, f: F) -> DbResult<T>
    where
        F: FnOnce(&Connection) -> DbResult<T>,
    {
        let tx = self.conn.transaction()?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.exists());
    }

    #[test]
    fn test_transaction() {
        let mut db = Database::open_in_memory().unwrap();

        let result = db.transaction(|conn| {
            conn.execute(
                "INSERT INTO projects (id, name, description, color, created_at, updated_at) 
                 VALUES ('test', 'Test', NULL, NULL, datetime('now'), datetime('now'))",
                [],
            )?;
            Ok(42)
        });

        assert_eq!(result.unwrap(), 42);

        // Verify insert persisted
        let count: i32 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM projects WHERE id = 'test'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_foreign_keys_enabled() {
        let db = Database::open_in_memory().unwrap();
        let enabled: i32 = db
            .conn()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(enabled, 1);
    }
}
