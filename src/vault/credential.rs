//! Credential Operations
//!
//! Encrypted CRUD operations for credentials.
//!
//! Credentials are encrypted with a Data Encryption Key (DEK), not the
//! master key directly.

use chrono::{DateTime, Local};
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::{decrypt_string, encrypt_string, DataEncryptionKey};
use crate::db::{self, Credential, CredentialType};

use super::{VaultError, VaultResult};

/// Decrypted credential for display
#[derive(Clone)]
pub struct DecryptedCredential {
    pub id: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub secret: Option<SecretString>,
    pub notes: Option<SecretString>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Local>,
    pub updated_at: DateTime<Local>,
}

impl DecryptedCredential {
    /// Create from encrypted credential
    pub fn from_credential(
        cred: &Credential,
        secret: Option<String>,
        notes: Option<String>,
    ) -> Self {
        Self {
            id: cred.id.clone(),
            name: cred.name.clone(),
            credential_type: cred.credential_type,
            username: cred.username.clone(),
            secret: secret.map(SecretString::from),
            notes: notes.map(SecretString::from),
            url: cred.url.clone(),
            tags: cred.tags.clone(),
            created_at: cred.created_at,
            updated_at: cred.updated_at,
        }
    }
}

/// Create a new credential (using DEK for encryption)
pub fn create_credential(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    name: String,
    credential_type: CredentialType,
    secret: &str,
    username: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
    notes: Option<&str>,
) -> VaultResult<Credential> {
    // Encrypt secret with DEK
    let encrypted_secret = encrypt_string(dek.as_ref(), secret)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Encrypt notes if provided
    let encrypted_notes = notes
        .map(|n| encrypt_string(dek.as_ref(), n))
        .transpose()
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Create credential
    let mut cred = Credential::new(name, credential_type, encrypted_secret);
    cred.username = username;
    cred.url = url;
    cred.tags = tags;
    cred.encrypted_notes = encrypted_notes;

    // Save to database
    db::create_credential(conn, &cred)?;

    Ok(cred)
}

/// Get a credential by ID
pub fn get_credential(conn: &rusqlite::Connection, id: &str) -> VaultResult<Credential> {
    Ok(db::get_credential(conn, id)?)
}

/// Decrypt a credential (using DEK)
pub fn decrypt_credential(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    cred: &Credential,
    log_access: bool,
) -> VaultResult<DecryptedCredential> {
    // Decrypt secret with DEK
    let secret = decrypt_string(dek.as_ref(), &cred.encrypted_secret)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Decrypt notes if present
    let notes = cred
        .encrypted_notes
        .as_ref()
        .map(|n| decrypt_string(dek.as_ref(), n))
        .transpose()
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Update access time
    if log_access {
        db::touch_credential(conn, &cred.id)?;
    }

    Ok(DecryptedCredential::from_credential(cred, Some(secret), notes))
}

/// Update a credential (using DEK)
pub fn update_credential(
    conn: &rusqlite::Connection,
    dek: &DataEncryptionKey,
    cred: &mut Credential,
    new_secret: Option<&str>,
    new_notes: Option<&str>,
) -> VaultResult<()> {
    // Re-encrypt secret if changed
    if let Some(secret) = new_secret {
        cred.encrypted_secret = encrypt_string(dek.as_ref(), secret)
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    }

    // Re-encrypt notes if changed or clear if None
    cred.encrypted_notes = match new_notes {
        Some(notes) if !notes.is_empty() => Some(
            encrypt_string(dek.as_ref(), notes)
                .map_err(|e| VaultError::CryptoError(e.to_string()))?,
        ),
        _ => None,
    };

    db::update_credential(conn, cred)?;

    Ok(())
}

/// Delete a credential
pub fn delete_credential(conn: &rusqlite::Connection, id: &str) -> VaultResult<()> {
    db::delete_credential(conn, id)?;
    Ok(())
}

/// List all credentials
pub fn list_credentials(conn: &rusqlite::Connection) -> VaultResult<Vec<Credential>> {
    Ok(db::get_all_credentials(conn)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DataEncryptionKey;
    use crate::db::Database;

    fn test_dek() -> DataEncryptionKey {
        DataEncryptionKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn test_create_and_decrypt() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();
        let dek = test_dek();

        let cred = create_credential(
            conn,
            &dek,
            "Test Credential".to_string(),
            CredentialType::Password,
            "my_secret_password",
            Some("testuser".to_string()),
            Some("https://example.com".to_string()),
            vec!["test".to_string()],
            Some("These are notes"),
        )
        .unwrap();

        let decrypted = decrypt_credential(conn, &dek, &cred, false).unwrap();

        assert_eq!(decrypted.name, "Test Credential");
        assert_eq!(
            decrypted.secret.as_ref().map(|s| s.expose_secret()),
            Some("my_secret_password")
        );
        assert_eq!(
            decrypted.notes.as_ref().map(|s| s.expose_secret()),
            Some("These are notes")
        );
        assert_eq!(decrypted.username, Some("testuser".to_string()));
    }

    #[test]
    fn test_update_credential() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();
        let dek = test_dek();

        let mut cred = create_credential(
            conn,
            &dek,
            "Test".to_string(),
            CredentialType::Password,
            "old_secret",
            None,
            None,
            vec![],
            None,
        )
        .unwrap();

        update_credential(conn, &dek, &mut cred, Some("new_secret"), Some("new notes")).unwrap();

        let fetched = get_credential(conn, &cred.id).unwrap();
        let decrypted = decrypt_credential(conn, &dek, &fetched, false).unwrap();

        assert_eq!(
            decrypted.secret.as_ref().map(|s| s.expose_secret()),
            Some("new_secret")
        );
        assert_eq!(
            decrypted.notes.as_ref().map(|s| s.expose_secret()),
            Some("new notes")
        );
    }

    #[test]
    fn test_delete_credential() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();
        let dek = test_dek();

        let cred = create_credential(
            conn,
            &dek,
            "Test".to_string(),
            CredentialType::Password,
            "secret",
            None,
            None,
            vec![],
            None,
        )
        .unwrap();

        delete_credential(conn, &cred.id).unwrap();
        assert!(get_credential(conn, &cred.id).is_err());
    }

    #[test]
    fn test_dek_change_simulation() {
        // This test verifies that credentials remain accessible
        // when the DEK stays the same (as happens during password change)
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        // Create DEK and credential
        let dek = DataEncryptionKey::generate();
        let cred = create_credential(
            conn,
            &dek,
            "Test".to_string(),
            CredentialType::Password,
            "secret_password",
            None,
            None,
            vec![],
            None,
        )
        .unwrap();

        // Simulate "password change" - DEK stays the same
        // (In real password change, only the wrapped DEK changes)
        let same_dek = DataEncryptionKey::from_bytes(*dek.as_bytes());

        // Verify credential is still accessible
        let decrypted = decrypt_credential(conn, &same_dek, &cred, false).unwrap();
        assert_eq!(
            decrypted.secret.as_ref().map(|s| s.expose_secret()),
            Some("secret_password")
        );
    }
}
