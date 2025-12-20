//! Key Hierarchy using HKDF
//!
//! Implements a hierarchical key derivation scheme:
//! Master Key -> Project Keys -> Credential Keys

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, CryptoResult, MasterKey};

/// A derived key for projects or credentials
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

/// Key hierarchy manager for deriving project and credential keys
pub struct KeyHierarchy {
    master_key: MasterKey,
}

impl KeyHierarchy {
    /// Create a new key hierarchy from master key
    pub fn new(master_key: MasterKey) -> Self {
        Self { master_key }
    }

    /// Derive a project-level key
    pub fn derive_project_key(&self, project_id: &str) -> CryptoResult<DerivedKey> {
        derive_key(self.master_key.as_bytes(), "project", project_id)
    }

    /// Derive a credential-level key under a project
    pub fn derive_credential_key(
        &self,
        project_id: &str,
        credential_id: &str,
    ) -> CryptoResult<DerivedKey> {
        // First derive project key, then credential key
        let project_key = self.derive_project_key(project_id)?;
        derive_key(project_key.as_bytes(), "credential", credential_id)
    }

    /// Derive a key for audit log HMAC
    pub fn derive_audit_key(&self) -> CryptoResult<DerivedKey> {
        derive_key(self.master_key.as_bytes(), "audit", "log")
    }

    /// Get reference to master key
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }
}

/// Derive a project key directly (convenience function)
pub fn derive_project_key(master_key: &MasterKey, project_id: &str) -> CryptoResult<DerivedKey> {
    derive_key(master_key.as_bytes(), "project", project_id)
}

/// Derive a credential key directly (convenience function)
pub fn derive_credential_key(
    project_key: &DerivedKey,
    credential_id: &str,
) -> CryptoResult<DerivedKey> {
    derive_key(project_key.as_bytes(), "credential", credential_id)
}

/// Core HKDF key derivation
fn derive_key(ikm: &[u8], context: &str, info: &str) -> CryptoResult<DerivedKey> {
    let salt = format!("credlock-{}", context);
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

    fn test_master_key() -> MasterKey {
        MasterKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn test_project_key_derivation() {
        let hierarchy = KeyHierarchy::new(test_master_key());

        let key1 = hierarchy.derive_project_key("project-1").unwrap();
        let key2 = hierarchy.derive_project_key("project-2").unwrap();

        // Different projects should have different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Same project should derive same key
        let key1_again = hierarchy.derive_project_key("project-1").unwrap();
        assert_eq!(key1.as_bytes(), key1_again.as_bytes());
    }

    #[test]
    fn test_credential_key_derivation() {
        let hierarchy = KeyHierarchy::new(test_master_key());

        let key1 = hierarchy
            .derive_credential_key("project-1", "cred-1")
            .unwrap();
        let key2 = hierarchy
            .derive_credential_key("project-1", "cred-2")
            .unwrap();
        let key3 = hierarchy
            .derive_credential_key("project-2", "cred-1")
            .unwrap();

        // Different credentials have different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        // Same credential ID in different projects have different keys
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_deterministic_derivation() {
        let master = test_master_key();
        let hierarchy1 = KeyHierarchy::new(master.clone());
        let hierarchy2 = KeyHierarchy::new(master);

        let key1 = hierarchy1.derive_credential_key("p1", "c1").unwrap();
        let key2 = hierarchy2.derive_credential_key("p1", "c1").unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }
}
