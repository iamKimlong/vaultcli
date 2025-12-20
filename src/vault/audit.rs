//! Audit Trail
//!
//! HMAC-signed audit logging for tamper detection.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::DerivedKey;
use crate::db::{self, AuditAction, AuditLog};

use super::VaultResult;

type HmacSha256 = Hmac<Sha256>;

/// Create an audit log entry with HMAC signature
pub fn log_action(
    conn: &rusqlite::Connection,
    audit_key: &DerivedKey,
    action: AuditAction,
    credential_id: Option<&str>,
    details: Option<&str>,
) -> VaultResult<i64> {
    let timestamp = chrono::Utc::now();
    
    // Build message to sign
    let message = format!(
        "{}:{}:{}:{}",
        timestamp.to_rfc3339(),
        action.as_str(),
        credential_id.unwrap_or(""),
        details.unwrap_or("")
    );

    // Compute HMAC
    let hmac = compute_hmac(audit_key.as_bytes(), &message);

    // Create log entry
    let log = AuditLog::new(
        action,
        credential_id.map(|s| s.to_string()),
        details.map(|s| s.to_string()),
        hmac,
    );

    let id = db::create_audit_log(conn, &log)?;
    Ok(id)
}

/// Verify an audit log entry's HMAC
pub fn verify_log(audit_key: &DerivedKey, log: &AuditLog) -> bool {
    let message = format!(
        "{}:{}:{}:{}",
        log.timestamp.to_rfc3339(),
        log.action.as_str(),
        log.credential_id.as_deref().unwrap_or(""),
        log.details.as_deref().unwrap_or("")
    );

    let expected_hmac = compute_hmac(audit_key.as_bytes(), &message);
    expected_hmac == log.hmac
}

/// Get recent audit logs
pub fn get_recent_logs(conn: &rusqlite::Connection, limit: usize) -> VaultResult<Vec<AuditLog>> {
    Ok(db::get_recent_audit_logs(conn, limit)?)
}

/// Get audit logs for a specific credential
pub fn get_credential_logs(conn: &rusqlite::Connection, credential_id: &str) -> VaultResult<Vec<AuditLog>> {
    Ok(db::get_credential_audit_logs(conn, credential_id)?)
}

/// Verify all audit logs in the database
pub fn verify_all_logs(conn: &rusqlite::Connection, audit_key: &DerivedKey) -> VaultResult<Vec<(AuditLog, bool)>> {
    let logs = db::get_recent_audit_logs(conn, 10000)?;
    let results: Vec<_> = logs
        .into_iter()
        .map(|log| {
            let valid = verify_log(audit_key, &log);
            (log, valid)
        })
        .collect();
    Ok(results)
}

fn compute_hmac(key: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyHierarchy, MasterKey};
    use crate::db::Database;

    fn test_audit_key() -> DerivedKey {
        let master = MasterKey::from_bytes([0x42u8; 32]);
        let hierarchy = KeyHierarchy::new(master);
        hierarchy.derive_audit_key().unwrap()
    }

    #[test]
    fn test_log_action() {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key();

        let id = log_action(
            db.conn(),
            &key,
            AuditAction::Create,
            Some("cred-123"),
            Some("Created new credential"),
        )
        .unwrap();

        assert!(id > 0);

        let logs = get_recent_logs(db.conn(), 10).unwrap();
        assert!(!logs.is_empty());
    }

    #[test]
    fn test_verify_log() {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key();

        log_action(
            db.conn(),
            &key,
            AuditAction::Read,
            Some("cred-456"),
            None,
        )
        .unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        let log = &logs[0];

        assert!(verify_log(&key, log));
    }

    #[test]
    fn test_tampered_log_fails_verification() {
        let db = Database::open_in_memory().unwrap();
        let key = test_audit_key();

        log_action(
            db.conn(),
            &key,
            AuditAction::Copy,
            Some("cred-789"),
            Some("Original details"),
        )
        .unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        let mut tampered_log = logs[0].clone();
        tampered_log.details = Some("Tampered details".to_string());

        assert!(!verify_log(&key, &tampered_log));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let db = Database::open_in_memory().unwrap();
        let key1 = test_audit_key();
        
        let master2 = MasterKey::from_bytes([0x43u8; 32]);
        let hierarchy2 = KeyHierarchy::new(master2);
        let key2 = hierarchy2.derive_audit_key().unwrap();

        log_action(db.conn(), &key1, AuditAction::Delete, Some("cred"), None).unwrap();

        let logs = get_recent_logs(db.conn(), 1).unwrap();
        assert!(!verify_log(&key2, &logs[0]));
    }
}
