//! Time-based One-Time Password (TOTP) Implementation
//!
//! Implements RFC 6238 for 2FA code generation.

use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use super::{CryptoError, CryptoResult};

/// TOTP secret configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    /// Base32-encoded secret
    pub secret: String,
    /// Account name (e.g., "user@example.com")
    pub account: String,
    /// Issuer (e.g., "GitHub")
    pub issuer: String,
    /// Number of digits (default: 6)
    pub digits: usize,
    /// Time step in seconds (default: 30)
    pub period: u64,
    /// Algorithm (default: SHA1)
    pub algorithm: TotpAlgorithm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub enum TotpAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl From<TotpAlgorithm> for Algorithm {
    fn from(algo: TotpAlgorithm) -> Self {
        match algo {
            TotpAlgorithm::SHA1 => Algorithm::SHA1,
            TotpAlgorithm::SHA256 => Algorithm::SHA256,
            TotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }
}

impl TotpSecret {
    /// Create a new TOTP secret with defaults
    pub fn new(secret: String, account: String, issuer: String) -> Self {
        Self {
            secret,
            account,
            issuer,
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::SHA1,
        }
    }

    /// Parse from otpauth:// URI
    pub fn from_uri(uri: &str) -> CryptoResult<Self> {
        let totp = TOTP::from_url(uri).map_err(|e| CryptoError::TotpFailed(e.to_string()))?;

        let algorithm = match totp.algorithm {
            Algorithm::SHA1 => TotpAlgorithm::SHA1,
            Algorithm::SHA256 => TotpAlgorithm::SHA256,
            Algorithm::SHA512 => TotpAlgorithm::SHA512,
        };

        Ok(Self {
            secret: totp.get_secret_base32(),
            account: totp.account_name.clone(),
            issuer: totp.issuer.clone().unwrap_or_default(),
            digits: totp.digits,
            period: totp.step,
            algorithm,
        })
    }

    /// Generate otpauth:// URI for QR code
    pub fn to_uri(&self) -> CryptoResult<String> {
        let totp = self.build_totp()?;
        Ok(totp.get_url())
    }

    fn build_totp(&self) -> CryptoResult<TOTP> {
        let secret = self.decode_secret()?;
        TOTP::new(
            self.algorithm.into(),
            self.digits,
            1,
            self.period,
            secret,
            Some(self.issuer.clone()),
            self.account.clone(),
        )
        .map_err(|e| CryptoError::TotpFailed(e.to_string()))
    }

    fn decode_secret(&self) -> CryptoResult<Vec<u8>> {
        Secret::Encoded(self.secret.clone())
            .to_bytes()
            .map_err(|e| CryptoError::TotpFailed(format!("Invalid base32 secret: {}", e)))
    }
}

/// Generate current TOTP code
pub fn generate_totp(secret: &TotpSecret) -> CryptoResult<String> {
    let totp = secret.build_totp()?;
    Ok(totp.generate_current().map_err(|e| CryptoError::TotpFailed(e.to_string()))?)
}

/// Generate TOTP code for a specific timestamp
pub fn generate_totp_at(secret: &TotpSecret, time: u64) -> CryptoResult<String> {
    let totp = secret.build_totp()?;
    Ok(totp.generate(time))
}

/// Get remaining seconds until code expires
pub fn time_remaining(secret: &TotpSecret) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secret.period - (now % secret.period)
}

/// Generate a new random TOTP secret (base32)
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 20]; // 160 bits
    rand::thread_rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;

        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp() {
        // Test vector from RFC 6238
        let secret = TotpSecret {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            account: "test@example.com".to_string(),
            issuer: "Test".to_string(),
            digits: 8,
            period: 30,
            algorithm: TotpAlgorithm::SHA1,
        };

        // Generate at a known timestamp
        let code = generate_totp_at(&secret, 59).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn test_totp_from_uri() {
        let uri = "otpauth://totp/ACME:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA1&digits=6&period=30";
        let secret = TotpSecret::from_uri(uri).unwrap();

        assert_eq!(secret.account, "john@example.com");
        assert_eq!(secret.issuer, "ACME");
        assert_eq!(secret.digits, 6);
        assert_eq!(secret.period, 30);
    }

    #[test]
    fn test_generate_secret() {
        let secret1 = generate_secret();
        let secret2 = generate_secret();

        assert!(!secret1.is_empty());
        assert_ne!(secret1, secret2);
        // Base32 alphabet check
        assert!(secret1.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn test_time_remaining() {
        let secret = TotpSecret::new(
            "JBSWY3DPEHPK3PXP".to_string(),
            "test".to_string(),
            "Test".to_string(),
        );
        let remaining = time_remaining(&secret);
        assert!(remaining <= 30);
        assert!(remaining >= 1);
    }
}
