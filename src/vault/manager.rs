//! Vault Manager
//!
//! Core vault state management, including database connection,
//! key hierarchy, and locking/unlocking.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::crypto::{
    derive_master_key, verify_master_key, KdfParams, KeyHierarchy, MasterKey,
};
use crate::db::{Database, DatabaseConfig};

use super::{VaultError, VaultResult};

/// Vault state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// Vault does not exist, needs initialization
    Uninitialized,
    /// Vault exists but is locked
    Locked,
    /// Vault is unlocked and ready
    Unlocked,
}

/// Vault configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Path to vault database
    pub path: PathBuf,
    /// Auto-lock timeout
    pub auto_lock_timeout: Duration,
}

impl Default for VaultConfig {
    fn default() -> Self {
        let path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("credlock")
            .join("vault.db");

        Self {
            path,
            auto_lock_timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl VaultConfig {
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }
}

/// Vault manager
pub struct Vault {
    /// Configuration
    config: VaultConfig,
    /// Database connection (when unlocked)
    db: Option<Database>,
    /// Key hierarchy (when unlocked)
    key_hierarchy: Option<KeyHierarchy>,
    /// Password hash (when unlocked)
    password_hash: Option<String>,
    /// Last activity time
    last_activity: Instant,
}

impl Vault {
    /// Create a new vault manager
    pub fn new(config: VaultConfig) -> Self {
        Self {
            config,
            db: None,
            key_hierarchy: None,
            password_hash: None,
            last_activity: Instant::now(),
        }
    }

    /// Create with default config
    pub fn with_default_config() -> Self {
        Self::new(VaultConfig::default())
    }

    /// Get current state
    pub fn state(&self) -> VaultState {
        if self.key_hierarchy.is_some() {
            VaultState::Unlocked
        } else if self.config.path.exists() {
            VaultState::Locked
        } else {
            VaultState::Uninitialized
        }
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.state() == VaultState::Unlocked
    }

    /// Initialize a new vault with password
    pub fn initialize(&mut self, password: &str) -> VaultResult<()> {
        if self.config.path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        // Create parent directory
        if let Some(parent) = self.config.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| VaultError::IoError(e.to_string()))?;
        }

        // Derive master key
        let params = KdfParams::default();
        let (master_key, password_hash) = derive_master_key(password.as_bytes(), &params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Create database
        let db_config = DatabaseConfig::with_path(&self.config.path);
        let db = Database::open(db_config)?;

        // Store password hash
        Self::store_password_hash(db.conn(), &password_hash)?;

        // Set up vault state
        self.db = Some(db);
        self.key_hierarchy = Some(KeyHierarchy::new(master_key));
        self.password_hash = Some(password_hash);
        self.update_activity();

        Ok(())
    }

    /// Unlock an existing vault
    pub fn unlock(&mut self, password: &str) -> VaultResult<()> {
        if !self.config.path.exists() {
            return Err(VaultError::NotFound);
        }

        // Open database
        let db_config = DatabaseConfig::with_path(&self.config.path);
        let db = Database::open(db_config)?;

        // Load and verify password
        let stored_hash = Self::load_password_hash(db.conn())?;
        let master_key = verify_master_key(password.as_bytes(), &stored_hash)
            .map_err(|_| VaultError::InvalidPassword)?;

        // Set up vault state
        self.db = Some(db);
        self.key_hierarchy = Some(KeyHierarchy::new(master_key));
        self.password_hash = Some(stored_hash);
        self.update_activity();

        Ok(())
    }

    /// Lock the vault
    pub fn lock(&mut self) {
        self.db = None;
        self.key_hierarchy = None;
        self.password_hash = None;
    }

    /// Check if auto-lock timeout has passed
    pub fn should_auto_lock(&self) -> bool {
        self.is_unlocked() && self.last_activity.elapsed() > self.config.auto_lock_timeout
    }

    /// Update activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get database reference
    pub fn db(&self) -> VaultResult<&Database> {
        self.db.as_ref().ok_or(VaultError::Locked)
    }

    /// Get key hierarchy reference
    pub fn keys(&self) -> VaultResult<&KeyHierarchy> {
        self.key_hierarchy.as_ref().ok_or(VaultError::Locked)
    }

    /// Get master key reference
    pub fn master_key(&self) -> VaultResult<&MasterKey> {
        Ok(self.keys()?.master_key())
    }

    /// Get vault configuration
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Store password hash in database
    fn store_password_hash(
        conn: &rusqlite::Connection,
        hash: &str,
    ) -> VaultResult<()> {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('password_hash', ?1)",
            [hash],
        )?;

        Ok(())
    }

    /// Load password hash from database
    fn load_password_hash(conn: &rusqlite::Connection) -> VaultResult<String> {
        conn.query_row(
            "SELECT value FROM metadata WHERE key = 'password_hash'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::NotFound)
    }

    /// Change master password
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> VaultResult<()> {
        // Verify old password
        let hash = self.password_hash.as_ref().ok_or(VaultError::Locked)?;
        verify_master_key(old_password.as_bytes(), hash)
            .map_err(|_| VaultError::InvalidPassword)?;

        // Derive new master key
        let params = KdfParams::default();
        let (new_master_key, new_hash) = derive_master_key(new_password.as_bytes(), &params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Store new password hash
        let db = self.db.as_ref().ok_or(VaultError::Locked)?;
        Self::store_password_hash(db.conn(), &new_hash)?;

        // Update in-memory state
        self.key_hierarchy = Some(KeyHierarchy::new(new_master_key));
        self.password_hash = Some(new_hash);
        self.update_activity();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_vault() -> (TempDir, VaultConfig) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test_vault.db");
        let config = VaultConfig::with_path(path);
        (dir, config)
    }

    #[test]
    fn test_vault_lifecycle() {
        let (_dir, config) = temp_vault();
        let mut vault = Vault::new(config);

        // Initially uninitialized
        assert_eq!(vault.state(), VaultState::Uninitialized);

        // Initialize
        vault.initialize("test_password").unwrap();
        assert_eq!(vault.state(), VaultState::Unlocked);

        // Lock
        vault.lock();
        assert_eq!(vault.state(), VaultState::Locked);

        // Unlock
        vault.unlock("test_password").unwrap();
        assert_eq!(vault.state(), VaultState::Unlocked);
    }

    #[test]
    fn test_wrong_password() {
        let (_dir, config) = temp_vault();
        let mut vault = Vault::new(config);

        vault.initialize("correct_password").unwrap();
        vault.lock();

        let result = vault.unlock("wrong_password");
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn test_change_password() {
        let (_dir, config) = temp_vault();
        let mut vault = Vault::new(config);

        vault.initialize("old_password").unwrap();
        vault.change_password("old_password", "new_password").unwrap();
        vault.lock();

        // Old password should fail
        assert!(vault.unlock("old_password").is_err());

        // New password should work
        vault.unlock("new_password").unwrap();
        assert!(vault.is_unlocked());
    }
}
