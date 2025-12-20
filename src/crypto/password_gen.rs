//! Password Generator
//!
//! Cryptographically secure password generation.

use rand::{seq::SliceRandom, Rng};
use rand::prelude::IteratorRandom; // provides .choose() for iterators

/// Password generation policy
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub length: usize,
    /// Include uppercase letters
    pub uppercase: bool,
    /// Include lowercase letters
    pub lowercase: bool,
    /// Include digits
    pub digits: bool,
    /// Include symbols
    pub symbols: bool,
    /// Custom symbols to use (if symbols is true)
    pub custom_symbols: Option<String>,
    /// Exclude ambiguous characters (0, O, l, 1, etc.)
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            custom_symbols: None,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordPolicy {
    /// Create a policy for PIN-style passwords
    pub fn pin(length: usize) -> Self {
        Self {
            length,
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
            custom_symbols: None,
            exclude_ambiguous: false,
        }
    }

    /// Create a policy for passphrase-friendly passwords
    pub fn readable(length: usize) -> Self {
        Self {
            length,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            custom_symbols: None,
            exclude_ambiguous: true,
        }
    }

    /// Create a maximum security policy
    pub fn maximum(length: usize) -> Self {
        Self {
            length,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            custom_symbols: Some("!@#$%^&*()_+-=[]{}|;:,.<>?".to_string()),
            exclude_ambiguous: false,
        }
    }
}

const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";
const AMBIGUOUS: &str = "0O1lI";

/// Generate a password using the given policy
pub fn generate_password(policy: &PasswordPolicy) -> String {
    let mut rng = rand::thread_rng();
    let mut charset = String::new();
    let mut required: Vec<char> = Vec::new();

    // Build character set and collect required characters
    if policy.uppercase {
        let chars: String = if policy.exclude_ambiguous {
            UPPERCASE.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect()
        } else {
            UPPERCASE.to_string()
        };
        if let Some(c) = chars.chars().choose(&mut rng) {
            required.push(c);
        }
        charset.push_str(&chars);
    }

    if policy.lowercase {
        let chars: String = if policy.exclude_ambiguous {
            LOWERCASE.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect()
        } else {
            LOWERCASE.to_string()
        };
        if let Some(c) = chars.chars().choose(&mut rng) {
            required.push(c);
        }
        charset.push_str(&chars);
    }

    if policy.digits {
        let chars: String = if policy.exclude_ambiguous {
            DIGITS.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect()
        } else {
            DIGITS.to_string()
        };
        if let Some(c) = chars.chars().choose(&mut rng) {
            required.push(c);
        }
        charset.push_str(&chars);
    }

    if policy.symbols {
        let chars = policy
            .custom_symbols
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(SYMBOLS);
        if let Some(c) = chars.chars().choose(&mut rng) {
            required.push(c);
        }
        charset.push_str(chars);
    }

    if charset.is_empty() {
        // Fallback to alphanumeric if no options selected
        charset = format!("{}{}{}", UPPERCASE, LOWERCASE, DIGITS);
    }

    let charset: Vec<char> = charset.chars().collect();

    // Generate password ensuring minimum requirements are met
    let remaining_length = policy.length.saturating_sub(required.len());
    let mut password: Vec<char> = required;

    for _ in 0..remaining_length {
        let idx = rng.gen_range(0..charset.len());
        password.push(charset[idx]);
    }

    // Shuffle to randomize position of required characters
    password.shuffle(&mut rng);

    password.into_iter().collect()
}

/// Generate a passphrase from wordlist
pub fn generate_passphrase(word_count: usize, separator: &str) -> String {
    // Simple wordlist - in production, use a proper wordlist like EFF's
    const WORDS: &[&str] = &[
        "apple", "banana", "cherry", "dragon", "eagle", "forest", "garden", "harbor",
        "island", "jungle", "knight", "lemon", "mountain", "noble", "ocean", "planet",
        "quantum", "river", "sunset", "thunder", "umbrella", "valley", "winter", "yellow",
        "zebra", "anchor", "bridge", "castle", "delta", "ember", "falcon", "glacier",
        "horizon", "ivory", "jasper", "karma", "lotus", "marble", "nebula", "orbit",
        "phoenix", "quartz", "radar", "safari", "temple", "ultra", "vertex", "whisper",
    ];

    let mut rng = rand::thread_rng();
    let words: Vec<&str> = (0..word_count)
        .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
        .collect();

    words.join(separator)
}

/// Calculate password strength (0-100)
pub fn password_strength(password: &str) -> u32 {
    let len = password.len();
    let mut score = 0u32;

    // Length contribution (up to 40 points)
    score += (len.min(20) * 2) as u32;

    // Character variety (up to 40 points)
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    if has_lower {
        score += 10;
    }
    if has_upper {
        score += 10;
    }
    if has_digit {
        score += 10;
    }
    if has_symbol {
        score += 10;
    }

    // Bonus for mixing (up to 20 points)
    let variety_count = [has_lower, has_upper, has_digit, has_symbol]
        .iter()
        .filter(|&&x| x)
        .count();
    score += (variety_count * 5) as u32;

    score.min(100)
}

/// Get strength label for a score
pub fn strength_label(score: u32) -> &'static str {
    match score {
        0..=20 => "Very Weak",
        21..=40 => "Weak",
        41..=60 => "Fair",
        61..=80 => "Strong",
        _ => "Very Strong",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default() {
        let policy = PasswordPolicy::default();
        let password = generate_password(&policy);

        assert_eq!(password.len(), 20);
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_pin() {
        let policy = PasswordPolicy::pin(6);
        let password = generate_password(&policy);

        assert_eq!(password.len(), 6);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_readable() {
        let policy = PasswordPolicy::readable(16);
        let password = generate_password(&policy);

        assert_eq!(password.len(), 16);
        // Should not contain ambiguous characters
        assert!(!password.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn test_generate_passphrase() {
        let passphrase = generate_passphrase(4, "-");
        let words: Vec<&str> = passphrase.split('-').collect();

        assert_eq!(words.len(), 4);
    }

    #[test]
    fn test_password_strength() {
        assert!(password_strength("abc") < 30);
        assert!(password_strength("Abc123!@#") > 60);
        assert!(password_strength("MyP@ssw0rd!2024XyZ") > 80);
    }

    #[test]
    fn test_unique_passwords() {
        let policy = PasswordPolicy::default();
        let p1 = generate_password(&policy);
        let p2 = generate_password(&policy);

        assert_ne!(p1, p2);
    }
}
