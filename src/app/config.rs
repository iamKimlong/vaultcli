use std::path::PathBuf;
use std::time::Duration;

pub struct AppConfig {
    pub vault_path: PathBuf,
    pub auto_lock_timeout: Duration,
    pub clipboard_timeout: Duration,
}

impl Default for AppConfig {
    fn default() -> Self {
        let vault_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vault")
            .join("vault.db");

        Self {
            vault_path,
            auto_lock_timeout: Duration::from_secs(300),
            clipboard_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PendingAction {
    DeleteCredential(String),
    LockVault,
    Quit,
}

impl PendingAction {
    pub fn confirm_message(&self) -> &'static str {
        match self {
            Self::DeleteCredential(_) => "Delete this credential?",
            Self::LockVault => "Lock the vault?",
            Self::Quit => "Quit Vault?",
        }
    }
}
