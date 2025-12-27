//! Key Hierarchy using HKDF
//!
//! Implements a hierarchical key derivation scheme:
//! - Master Key (from password) -> wraps DEK
//! - DEK (Data Encryption Key) -> encrypts credentials

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::dek::DataEncryptionKey;
use super::{CryptoError, CryptoResult, MasterKey};

/// A derived key for credentials
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    key: [u8; 32],
}

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Convert to MasterKey for encryption operations
    pub fn to_master_key(&self) -> MasterKey {
        MasterKey::from_bytes(self.key)
    }
}

/// Key hierarchy manager
pub struct KeyHierarchy {
    /// Master key (derived from password)
    /// Used only for wrapping/unwrapping the DEK
    master_key: MasterKey,

    /// Data Encryption Key
    /// Used for encrypting all credential data
    dek: DataEncryptionKey,

    /// Wrapped DEK (encrypted with master key)
    /// Stored in database for persistence
    wrapped_dek: String,
}

impl KeyHierarchy {
    /// Create a new key hierarchy for vault initialization
    /// Generates a fresh DEK and wraps it with the master key
    pub fn new(master_key: MasterKey) -> CryptoResult<Self> {
        let dek = DataEncryptionKey::generate();
        let wrapped_dek = dek.wrap(&master_key)?;

        Ok(Self {
            master_key,
            dek,
            wrapped_dek,
        })
    }

    /// Restore key hierarchy from stored wrapped DEK
    /// Used when unlocking an existing vault
    pub fn from_wrapped_dek(master_key: MasterKey, wrapped_dek: String) -> CryptoResult<Self> {
        let dek = DataEncryptionKey::unwrap(&wrapped_dek, &master_key)?;

        Ok(Self {
            master_key,
            dek,
            wrapped_dek,
        })
    }

    /// Change the master key (password change)
    /// Re-wraps the DEK with the new master key
    /// Returns the new wrapped DEK for storage
    pub fn change_master_key(&mut self, new_master_key: MasterKey) -> CryptoResult<String> {
        // Re-wrap DEK with new master key
        let new_wrapped_dek = self.dek.rewrap(&new_master_key)?;

        // Update internal state
        self.master_key = new_master_key;
        self.wrapped_dek = new_wrapped_dek.clone();

        Ok(new_wrapped_dek)
    }

    /// Get the wrapped DEK for storage
    pub fn wrapped_dek(&self) -> &str {
        &self.wrapped_dek
    }

    /// Get the DEK for credential encryption
    pub fn dek(&self) -> &DataEncryptionKey {
        &self.dek
    }

    /// Get reference to master key
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    /// Derive a credential-level key
    pub fn derive_credential_key(&self, credential_id: &str) -> CryptoResult<DerivedKey> {
        derive_key(self.dek.as_bytes(), "credential", credential_id)
    }

    /// Derive a key for audit log HMAC
    pub fn derive_audit_key(&self) -> CryptoResult<DerivedKey> {
        derive_key(self.dek.as_bytes(), "audit", "log")
    }
}

/// Derive a credential key directly (convenience function)
pub fn derive_credential_key(
    dek: &DataEncryptionKey,
    credential_id: &str,
) -> CryptoResult<DerivedKey> {
    derive_key(dek.as_bytes(), "credential", credential_id)
}

/// Core HKDF key derivation
fn derive_key(ikm: &[u8], context: &str, info: &str) -> CryptoResult<DerivedKey> {
    let salt = format!("vault-{}", context);
    let info_bytes = format!("{}:{}", context, info);

    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm);

    let mut okm = [0u8; 32];
    hk.expand(info_bytes.as_bytes(), &mut okm)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(DerivedKey { key: okm })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_master_key, KdfParams};

    fn test_master_key() -> MasterKey {
        MasterKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn test_new_hierarchy() {
        let master_key = test_master_key();
        let hierarchy = KeyHierarchy::new(master_key).unwrap();

        // Should have a wrapped DEK
        assert!(!hierarchy.wrapped_dek().is_empty());
    }

    #[test]
    fn test_restore_from_wrapped_dek() {
        let master_key = test_master_key();

        // Create hierarchy and save wrapped DEK
        let hierarchy1 = KeyHierarchy::new(master_key.clone()).unwrap();
        let wrapped_dek = hierarchy1.wrapped_dek().to_string();

        // Restore hierarchy from wrapped DEK
        let hierarchy2 = KeyHierarchy::from_wrapped_dek(master_key, wrapped_dek).unwrap();

        // DEKs should match
        assert_eq!(hierarchy1.dek().as_bytes(), hierarchy2.dek().as_bytes());
    }

    #[test]
    fn test_password_change() {
        let params = KdfParams::testing();

        // Initial setup
        let (old_master_key, _) = derive_master_key(b"old_password", &params).unwrap();
        let mut hierarchy = KeyHierarchy::new(old_master_key).unwrap();
        let original_dek = hierarchy.dek().as_bytes().clone();

        // Change password
        let (new_master_key, _) = derive_master_key(b"new_password", &params).unwrap();
        let new_wrapped_dek = hierarchy.change_master_key(new_master_key.clone()).unwrap();

        // DEK should remain the same
        assert_eq!(&original_dek, hierarchy.dek().as_bytes());

        // Should be able to restore with new password
        let restored = KeyHierarchy::from_wrapped_dek(new_master_key, new_wrapped_dek).unwrap();
        assert_eq!(&original_dek, restored.dek().as_bytes());
    }

    #[test]
    fn test_credential_key_derivation() {
        let hierarchy = KeyHierarchy::new(test_master_key()).unwrap();

        let key1 = hierarchy.derive_credential_key("cred-1").unwrap();
        let key2 = hierarchy.derive_credential_key("cred-2").unwrap();

        // Different credentials have different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Same credential should derive same key
        let key1_again = hierarchy.derive_credential_key("cred-1").unwrap();
        assert_eq!(key1.as_bytes(), key1_again.as_bytes());
    }

    #[test]
    fn test_deterministic_derivation_after_password_change() {
        let params = KdfParams::testing();

        // Create initial hierarchy
        let (master_key1, _) = derive_master_key(b"password1", &params).unwrap();
        let mut hierarchy = KeyHierarchy::new(master_key1).unwrap();

        // Derive some keys
        let cred_key_before = hierarchy.derive_credential_key("cred-1").unwrap();

        // Change password
        let (master_key2, _) = derive_master_key(b"password2", &params).unwrap();
        hierarchy.change_master_key(master_key2).unwrap();

        // Derived keys should be identical (DEK unchanged)
        let cred_key_after = hierarchy.derive_credential_key("cred-1").unwrap();

        assert_eq!(cred_key_before.as_bytes(), cred_key_after.as_bytes());
    }
}
