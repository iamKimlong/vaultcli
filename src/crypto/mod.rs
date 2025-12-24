//! Cryptographic Operations
//!
//! Provides secure encryption, key derivation, and password generation.

pub mod dek;
pub mod encryption;
pub mod kdf;
pub mod key_hierarchy;
pub mod password_gen;
pub mod totp;

use thiserror::Error;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),

    #[error("TOTP generation failed: {0}")]
    TotpFailed(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// Re-exports
pub use dek::DataEncryptionKey;
pub use encryption::{decrypt_bytes, decrypt_string, encrypt_bytes, encrypt_string};
pub use kdf::{derive_master_key, verify_master_key, KdfParams, MasterKey};
pub use key_hierarchy::{DerivedKey, KeyHierarchy};
pub use password_gen::{generate_password, password_strength, strength_label, PasswordPolicy};
pub use totp::{generate_totp, time_remaining, TotpSecret};
