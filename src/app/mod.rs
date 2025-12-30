//! Application State
//!
//! Core application logic tying together vault, UI, and input.

mod actions;
mod clipboard;
mod config;
mod credentials;
mod input;

use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::db::models::Credential;
use crate::db::AuditAction;
use crate::input::modes::ModeState;
use crate::ui::components::popup::{HelpState, LogsState, TagsState};
use crate::ui::components::{CredentialDetail, CredentialForm, CredentialItem, ListViewState, MessageType};
use crate::ui::renderer::{Renderer, UiState, View};
use crate::vault::credential::DecryptedCredential;
use crate::vault::manager::VaultState;
use crate::vault::{audit, Vault};

pub use config::{AppConfig, PendingAction};

pub struct App {
    pub config: AppConfig,
    pub vault: Vault,
    pub mode_state: ModeState,
    pub view: View,
    pub terminal_size: Rect,
    pub list_state: ListViewState,
    pub credentials: Vec<Credential>,
    pub credential_items: Vec<CredentialItem>,
    pub selected_credential: Option<DecryptedCredential>,
    pub selected_detail: Option<CredentialDetail>,
    pub message: Option<(String, MessageType, Instant)>,
    pub pending_action: Option<PendingAction>,
    pub password_visible: bool,
    pub should_quit: bool,
    pub credential_form: Option<CredentialForm>,
    pub wants_password_change: bool,
    pub help_state: HelpState,
    pub logs_state: LogsState,
    pub tags_state: TagsState,
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let vault_config = crate::vault::VaultConfig::with_path(&config.vault_path);

        Self {
            vault: Vault::new(vault_config),
            config,
            mode_state: ModeState::new(),
            view: View::List,
            terminal_size: Rect::default(),
            list_state: ListViewState::new(),
            credentials: Vec::new(),
            credential_items: Vec::new(),
            selected_credential: None,
            selected_detail: None,
            message: None,
            pending_action: None,
            password_visible: false,
            should_quit: false,
            credential_form: None,
            wants_password_change: false,
            help_state: HelpState::new(),
            logs_state: LogsState::new(),
            tags_state: TagsState::new(),
        }
    }

    pub fn needs_init(&self) -> bool {
        self.vault.state() == VaultState::Uninitialized
    }

    pub fn is_locked(&self) -> bool {
        self.vault.state() == VaultState::Locked
    }

    pub fn initialize(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vault.initialize(password)?;
        self.log_audit(AuditAction::Unlock, None, None, None, Some("Vault Initialized!"))?;
        self.refresh_data()
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vault.unlock(password)?;
        self.handle_failed_attempts()?;
        self.check_audit_integrity();
        self.log_audit(AuditAction::Unlock, None, None, None, None)?;
        self.refresh_data()?;
        self.update_selected_detail()
    }

    fn handle_failed_attempts(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some((count, timestamp)) = self.vault.take_pending_failed_attempts()? else {
            return Ok(());
        };

        let details = format!("{} unlock attempt(s) on {}", count, timestamp);
        self.log_audit(AuditAction::FailedUnlock, None, None, None, Some(&details))?;
        self.set_message(&format!("Warning: {} failed unlock attempt(s) detected", count), MessageType::Error);
        Ok(())
    }

    fn check_audit_integrity(&mut self) {
        let Ok((tampered, total)) = self.verify_audit_logs() else { return };
        if tampered == 0 { return }
        self.set_message(
            &format!("Warning: {} of {} audit logs may be tampered", tampered, total),
            MessageType::Error,
        );
    }

    pub fn lock(&mut self) {
        let _ = self.log_audit(AuditAction::Lock, None, None, None, None);
        self.vault.lock();
        self.clear_credentials();
    }

    pub fn log_audit(
        &self,
        action: AuditAction,
        credential_id: Option<&str>,
        credential_name: Option<&str>,
        username: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        audit::log_action(db.conn(), &audit_key, action, credential_id, credential_name, username, details)?;
        Ok(())
    }

    fn verify_audit_logs(&self) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        let results = audit::verify_all_logs(db.conn(), &audit_key)?;
        let total = results.len();
        let tampered = results.iter().filter(|(_, valid)| !valid).count();
        Ok((tampered, total))
    }

    fn load_audit_logs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let _audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        let logs = crate::vault::audit::get_recent_logs(db.conn(), 500)?;
        self.logs_state.set_logs(logs);
        Ok(())
    }

    fn load_tags(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.tags_state.set_tags_from_credentials(&self.credentials);
        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame) {
        self.terminal_size = frame.area();
        self.check_message_expiry();

        let message = self.message.as_ref().map(|(m, t, _)| (m.as_str(), *t));
        let command_buffer = self.mode_state.mode.is_text_input().then(|| self.mode_state.get_buffer());
        let confirm_message = self.pending_action.as_ref().map(|a| a.confirm_message());

        let mut state = UiState {
            view: self.view,
            mode: self.mode_state.mode,
            credentials: &self.credential_items,
            list_state: &mut self.list_state,
            selected_detail: self.selected_detail.as_ref(),
            command_buffer,
            message,
            confirm_message,
            password_prompt: None,
            credential_form: self.credential_form.as_ref(),
            help_state: &self.help_state,
            logs_state: &self.logs_state,
            tags_state: &self.tags_state,
        };

        Renderer::render(frame, &mut state);
    }

    fn check_message_expiry(&mut self) {
        let expired = self
            .message
            .as_ref()
            .is_some_and(|(_, _, time)| time.elapsed() > Duration::from_secs(5));

        if expired {
            self.message = None;
        }
    }

    pub fn set_message(&mut self, msg: &str, msg_type: MessageType) {
        self.message = Some((msg.to_string(), msg_type, Instant::now()));
    }
}
