//! Vault Manager
//!
//! Core vault state, including storage, key management, and lock/unlock flow.
//!
//! Uses a wrapped DEK (Data Encryption Key) model so password changes do not
//! require re-encrypting stored data.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::crypto::{
    derive_master_key, verify_master_key, DataEncryptionKey, KdfParams, KeyHierarchy, MasterKey,
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

        // Derive master key from password
        let params = KdfParams::default();
        let (master_key, password_hash) = derive_master_key(password.as_bytes(), &params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Create key hierarchy (generates DEK and wraps it)
        let key_hierarchy = KeyHierarchy::new(master_key)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Create database
        let db_config = DatabaseConfig::with_path(&self.config.path);
        let db = Database::open(db_config)?;

        // Store password hash and wrapped DEK
        Self::store_password_hash(db.conn(), &password_hash)?;
        Self::store_wrapped_dek(db.conn(), key_hierarchy.wrapped_dek())?;

        // Set up vault state
        self.db = Some(db);
        self.key_hierarchy = Some(key_hierarchy);
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

        // Load wrapped DEK and reconstruct key hierarchy
        let wrapped_dek = Self::load_wrapped_dek(db.conn())?;
        let key_hierarchy = KeyHierarchy::from_wrapped_dek(master_key, wrapped_dek)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Set up vault state
        self.db = Some(db);
        self.key_hierarchy = Some(key_hierarchy);
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

    /// Get DEK reference for encryption operations
    pub fn dek(&self) -> VaultResult<&DataEncryptionKey> {
        Ok(self.keys()?.dek())
    }

    /// Get master key reference (prefer using dek() for encryption)
    pub fn master_key(&self) -> VaultResult<&MasterKey> {
        Ok(self.keys()?.master_key())
    }

    /// Verify if the provided password matches the current master password
    pub fn verify_password(&self, password: &str) -> VaultResult<()> {
        let hash = self.password_hash.as_ref().ok_or(VaultError::Locked)?;
        verify_master_key(password.as_bytes(), hash)
            .map_err(|_| VaultError::InvalidPassword)?;
        Ok(())
    }

    /// Get vault configuration
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Store password hash in database
    fn store_password_hash(conn: &rusqlite::Connection, hash: &str) -> VaultResult<()> {
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

    /// Store wrapped DEK in database
    fn store_wrapped_dek(conn: &rusqlite::Connection, wrapped_dek: &str) -> VaultResult<()> {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('wrapped_dek', ?1)",
            [wrapped_dek],
        )?;
        Ok(())
    }

    /// Load wrapped DEK from database
    fn load_wrapped_dek(conn: &rusqlite::Connection) -> VaultResult<String> {
        conn.query_row(
            "SELECT value FROM metadata WHERE key = 'wrapped_dek'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::NotFound)
    }

    /// Change master password
    /// Credentials remain encrypted with the same DEK
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> VaultResult<()> {
        // Verify old password
        let hash = self.password_hash.as_ref().ok_or(VaultError::Locked)?;
        verify_master_key(old_password.as_bytes(), hash)
            .map_err(|_| VaultError::InvalidPassword)?;

        // Derive new master key
        let params = KdfParams::default();
        let (new_master_key, new_hash) = derive_master_key(new_password.as_bytes(), &params)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Re-wrap DEK with new master key
        let key_hierarchy = self.key_hierarchy.as_mut().ok_or(VaultError::Locked)?;
        let new_wrapped_dek = key_hierarchy
            .change_master_key(new_master_key)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Store new password hash and wrapped DEK
        let db = self.db.as_ref().ok_or(VaultError::Locked)?;
        Self::store_password_hash(db.conn(), &new_hash)?;
        Self::store_wrapped_dek(db.conn(), &new_wrapped_dek)?;

        // Update in-memory state
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

        // Verify DEK exists
        assert!(vault.dek().is_ok());

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

        // Get DEK before password change
        let dek_before = vault.dek().unwrap().as_bytes().clone();

        // Change password
        vault
            .change_password("old_password", "new_password")
            .unwrap();

        // DEK should remain the same
        let dek_after = vault.dek().unwrap().as_bytes();
        assert_eq!(&dek_before, dek_after);

        vault.lock();

        // Old password should fail
        assert!(vault.unlock("old_password").is_err());

        // New password should work
        vault.unlock("new_password").unwrap();
        assert!(vault.is_unlocked());

        // DEK should still be the same
        assert_eq!(&dek_before, vault.dek().unwrap().as_bytes());
    }

    #[test]
    fn test_credentials_accessible_after_password_change() {
        use crate::crypto::{decrypt_string, encrypt_string};

        let (_dir, config) = temp_vault();
        let mut vault = Vault::new(config);

        vault.initialize("password1").unwrap();

        // Encrypt some data with DEK
        let secret = "my_secret_data";
        let encrypted = encrypt_string(vault.dek().unwrap().as_ref(), secret).unwrap();

        // Change password
        vault.change_password("password1", "password2").unwrap();

        // Data should still be decryptable with (same) DEK
        let decrypted = decrypt_string(vault.dek().unwrap().as_ref(), &encrypted).unwrap();
        assert_eq!(secret, decrypted);

        // Lock and unlock with new password
        vault.lock();
        vault.unlock("password2").unwrap();

        // Data should still be decryptable
        let decrypted = decrypt_string(vault.dek().unwrap().as_ref(), &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_wrapped_dek_stored() {
        let (_dir, config) = temp_vault();
        let mut vault = Vault::new(config);

        vault.initialize("password").unwrap();

        // Verify wrapped DEK is stored
        let db = vault.db().unwrap();
        let wrapped_dek: String = db
            .conn()
            .query_row(
                "SELECT value FROM metadata WHERE key = 'wrapped_dek'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(!wrapped_dek.is_empty());
    }
}
