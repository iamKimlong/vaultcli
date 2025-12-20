//! Encryption Module
//!
//! ChaCha20-Poly1305 AEAD encryption for credential secrets.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

use super::{CryptoError, CryptoResult};

/// Nonce size for ChaCha20-Poly1305 (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Encrypted blob with nonce prepended
pub type EncryptedBlob = String;

/// Encrypt a string using ChaCha20-Poly1305
pub fn encrypt_string(key: &[u8], plaintext: &str) -> CryptoResult<EncryptedBlob> {
    encrypt_bytes(key, plaintext.as_bytes())
}

/// Decrypt a string using ChaCha20-Poly1305
pub fn decrypt_string(key: &[u8], ciphertext: &EncryptedBlob) -> CryptoResult<String> {
    let bytes = decrypt_bytes(key, ciphertext)?;
    String::from_utf8(bytes).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt bytes using ChaCha20-Poly1305
pub fn encrypt_bytes(key: &[u8], plaintext: &[u8]) -> CryptoResult<EncryptedBlob> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext and encode as hex
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);

    Ok(hex::encode(result))
}

/// Decrypt bytes using ChaCha20-Poly1305
pub fn decrypt_bytes(key: &[u8], ciphertext: &EncryptedBlob) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    // Decode from hex
    let data = hex::decode(ciphertext).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    if data.len() < NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "Ciphertext too short".to_string(),
        ));
    }

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext_bytes) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext_bytes)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let key = test_key();
        let plaintext = "Hello, World!";

        let encrypted = encrypt_string(&key, plaintext).unwrap();
        let decrypted = decrypt_string(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let key = test_key();
        let plaintext = b"Binary data \x00\x01\x02";

        let encrypted = encrypt_bytes(&key, plaintext).unwrap();
        let decrypted = decrypt_bytes(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_nonces() {
        let key = test_key();
        let plaintext = "Same message";

        let encrypted1 = encrypt_string(&key, plaintext).unwrap();
        let encrypted2 = encrypt_string(&key, plaintext).unwrap();

        // Same plaintext should produce different ciphertexts due to random nonces
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        assert_eq!(decrypt_string(&key, &encrypted1).unwrap(), plaintext);
        assert_eq!(decrypt_string(&key, &encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = "Secret";

        let encrypted = encrypt_string(&key1, plaintext).unwrap();
        let result = decrypt_string(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        let result = encrypt_string(&short_key, "test");
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength(16))));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = "Secret message";

        let mut encrypted = encrypt_string(&key, plaintext).unwrap();

        // Tamper with the ciphertext (flip a bit in the middle)
        let mut bytes: Vec<u8> = hex::decode(&encrypted).unwrap();
        if bytes.len() > NONCE_SIZE + 5 {
            bytes[NONCE_SIZE + 5] ^= 0x01;
        }
        encrypted = hex::encode(bytes);

        let result = decrypt_string(&key, &encrypted);
        assert!(result.is_err());
    }
}
