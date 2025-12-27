//! Application State
//!
//! Core application logic tying together vault, UI, and input.

use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroize;
use secrecy::ExposeSecret;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;

use crate::crypto::totp::{self, TotpSecret};
use crate::db::models::{Credential, CredentialType};
use crate::db::AuditAction;
use crate::input::keymap::{
    confirm_action, help_action, normal_mode_action, parse_command, text_input_action, Action,
};
use crate::input::modes::{InputMode, ModeState};
use crate::ui::components::{CredentialDetail, CredentialForm, CredentialItem, ListViewState, LogsState, MessageType};
use crate::ui::renderer::{Renderer, UiState, View};
use crate::ui::components::popup::HelpState;
use crate::vault::credential::DecryptedCredential;
use crate::vault::manager::VaultState;
use crate::vault::{audit, Vault};

static CLIPBOARD_COPY_ID: AtomicU64 = AtomicU64::new(0);

/// Application configuration
pub struct AppConfig {
    pub vault_path: PathBuf,
    pub auto_lock_timeout: Duration,
    pub clipboard_timeout: Duration,
}

impl Default for AppConfig {
    fn default() -> Self {
        let vault_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vault-cli")
            .join("vault.db");

        Self {
            vault_path,
            auto_lock_timeout: Duration::from_secs(300),
            clipboard_timeout: Duration::from_secs(15),
        }
    }
}

/// Pending confirmation action
#[derive(Debug, Clone)]
pub enum PendingAction {
    DeleteCredential(String),
    LockVault,
    Quit,
}

/// Main application state
pub struct App {
    pub config: AppConfig,
    pub vault: Vault,
    pub mode_state: ModeState,
    pub view: View,
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
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let vault_config = crate::vault::VaultConfig::with_path(&config.vault_path);
        
        Self {
            vault: Vault::new(vault_config),
            config,
            mode_state: ModeState::new(),
            view: View::List,
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
        }
    }

    /// Check if vault needs initialization
    pub fn needs_init(&self) -> bool {
        self.vault.state() == VaultState::Uninitialized
    }

    /// Check if vault is locked
    pub fn is_locked(&self) -> bool {
        self.vault.state() == VaultState::Locked
    }

    /// Initialize vault with password
    pub fn initialize(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vault.initialize(password)?;
        self.log_audit(AuditAction::Unlock, None, Some("vault initialized"))?;
        self.refresh_data()?;
        Ok(())
    }

    /// Unlock vault with password
    pub fn unlock(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vault.unlock(password)?;

        // Verify audit log integrity
        match self.verify_audit_logs() {
            Ok((0, total)) if total > 0 => {
                // All logs valid, no message needed
            }
            Ok((tampered, total)) if tampered > 0 => {
                self.set_message(
                    &format!("Warning: {} of {} audit logs may be tampered", tampered, total),
                    MessageType::Error,
                );
            }
            _ => {}
        }
        self.log_audit(AuditAction::Unlock, None, None)?;
        self.refresh_data()?;
        self.update_selected_detail()?;
        Ok(())
    }

    /// Clear credentials in memory
    pub fn clear_credential(&mut self) {
        self.credentials.clear();
        self.credential_items.clear();
        self.selected_credential = None;
        self.selected_detail = None;
    }

    /// Lock vault
    pub fn lock(&mut self) {
        // Log before locking (need keys to compute HMAC)
        let _ = self.log_audit(AuditAction::Lock, None, None);
        self.vault.lock();
        self.clear_credential();
    }

    /// Log an audit action with HMAC
    fn log_audit(
        &self,
        action: AuditAction,
        credential_id: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        audit::log_action(db.conn(), &audit_key, action, credential_id, details)?;
        Ok(())
    }

    /// Verify all audit logs and return count of tampered entries
    fn verify_audit_logs(&self) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        let results = audit::verify_all_logs(db.conn(), &audit_key)?;
        let total = results.len();
        let tampered = results.iter().filter(|(_, valid)| !valid).count();
        Ok((tampered, total))
    }

    /// Load audit logs into logs_state
    fn load_audit_logs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let keys = self.vault.keys()?;
        let audit_key = keys.derive_audit_key()?;
        let db = self.vault.db()?;
        
        // Get recent logs (most recent first is default from DB)
        let logs = crate::vault::audit::get_recent_logs(db.conn(), 500)?;
        self.logs_state.set_logs(logs);
        
        Ok(())
    }

    /// Refresh data from vault
    pub fn refresh_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        
        self.credentials = crate::db::get_all_credentials(db.conn())?;
        
        self.credential_items = self.credentials
            .iter()
            .map(|c| self.credential_to_item(c))
            .collect();
        
        self.list_state.set_total(self.credential_items.len());
        
        Ok(())
    }

    fn credential_to_item(&self, cred: &Credential) -> CredentialItem {
        CredentialItem {
            id: cred.id.clone(),
            name: cred.name.clone(),
            username: cred.username.clone(),
            credential_type: cred.credential_type,
            tags: cred.tags.clone(),
        }
    }

    /// Render the application
    pub fn render(&mut self, frame: &mut Frame) {
        self.check_message_expiry();

        let message = self.message.as_ref().map(|(m, t, _)| (m.as_str(), *t));
        let command_buffer = if self.mode_state.mode.is_text_input() {
            Some(self.mode_state.get_buffer())
        } else {
            None
        };

        let confirm_message = self.pending_action.as_ref().map(|a| match a {
            PendingAction::DeleteCredential(_) => "Delete this credential?",
            PendingAction::LockVault => "Lock the vault?",
            PendingAction::Quit => "Quit Vault-CLI?",
        });

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
        };

        Renderer::render(frame, &mut state);
    }

    fn check_message_expiry(&mut self) {
        if let Some((_, _, time)) = &self.message {
            if time.elapsed() > Duration::from_secs(5) {
                self.message = None;
            }
        }
    }

    pub fn set_message(&mut self, msg: &str, msg_type: MessageType) {
        self.message = Some((msg.to_string(), msg_type, Instant::now()));
    }

    /// Handle key event
    pub fn handle_key_event(&mut self, key: KeyEvent) -> Result<bool, Box<dyn std::error::Error>> {
        if key.kind != KeyEventKind::Press {
            return Ok(false);
        }

        // Handle form input separately
        if self.view == View::Form && self.credential_form.is_some() {
            return self.handle_form_key(key);
        }

        let action = match self.mode_state.mode {
            InputMode::Normal => {
                let (action, pending) = normal_mode_action(key, self.mode_state.pending);
                self.mode_state.pending = pending;
                action
            }
            InputMode::Command | InputMode::Search | InputMode::Filter => {
                let action = text_input_action(key);
                self.handle_text_input(action)
            }
            InputMode::Confirm => confirm_action(key),
            InputMode::Help => {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('?') => {
                        self.mode_state.to_normal();
                        return Ok(false);
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        let max = crate::ui::components::popup::HelpScreen::max_scroll(20);
                        self.help_state.scroll_down(1, max);
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.help_state.scroll_up(1);
                    }
                    KeyCode::Char('g') => {
                        self.help_state.home();
                    }
                    KeyCode::Char('G') => {
                        let max = crate::ui::components::popup::HelpScreen::max_scroll(20);
                        self.help_state.end(max);
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let max = crate::ui::components::popup::HelpScreen::max_scroll(20);
                        self.help_state.scroll_down(10, max);
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.help_state.scroll_up(10);
                    }
                    _ => {}
                }
                return Ok(false);
            }
            InputMode::Logs => {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('i') | KeyCode::Esc => {
                        self.mode_state.to_normal();
                        return Ok(false);
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        let max = self.logs_state.max_scroll(20);
                        self.logs_state.scroll_down(1, max);
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.logs_state.scroll_up(1);
                    }
                    KeyCode::Char('g') => {
                        self.logs_state.home();
                    }
                    KeyCode::Char('G') => {
                        let max = self.logs_state.max_scroll(20);
                        self.logs_state.end(max);
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let max = self.logs_state.max_scroll(20);
                        self.logs_state.scroll_down(10, max);
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.logs_state.scroll_up(10);
                    }
                    _ => {}
                }
                return Ok(false);
            }
            _ => Action::None,
        };

        self.execute_action(action)
    }

    /// Handle key events in form mode
    fn handle_form_key(&mut self, key: KeyEvent) -> Result<bool, Box<dyn std::error::Error>> {
        let form = self.credential_form.as_mut().unwrap();
        let return_to = form.previous_view.clone();

        match (key.code, key.modifiers) {
            // Cancel form
            (KeyCode::Esc, _) => {
                self.credential_form = None;
                self.view = return_to;
            }
            // Submit form
            (KeyCode::Enter, KeyModifiers::NONE) => {
                if let Err(e) = form.validate() {
                    self.set_message(&e, MessageType::Error);
                } else {
                    self.save_credential_form()?;
                }
            }
            // Next field
            (KeyCode::Tab, KeyModifiers::NONE) | (KeyCode::Down, _) => {
                form.next_field();
            }
            // Previous field
            (KeyCode::BackTab, _) | (KeyCode::Up, _) => {
                form.prev_field();
            }
            // Toggle password visibility
            (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
                form.toggle_password_visibility();
            }
            // Cycle forward type (for select fields)
            (KeyCode::Char(' '), KeyModifiers::NONE) if form.active_field().field_type == crate::ui::components::form::FieldType::Select => {
                form.cycle_type(true);
            }
            // Cycle backward type (for select fields)
            (KeyCode::Char(' '), KeyModifiers::CONTROL) if form.active_field().field_type == crate::ui::components::form::FieldType::Select => {
                form.cycle_type(false);
            }
            // Text input
            (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                form.insert_char(c);
            }
            (KeyCode::Backspace, _) => {
                form.delete_char();
            }
            (KeyCode::Left, _) => {
                form.cursor_left();
            }
            (KeyCode::Right, _) => {
                form.cursor_right();
            }
            _ => {}
        }

        Ok(false)
    }

    /// Save the credential form (create or update)
    fn save_credential_form(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let form = self.credential_form.take().unwrap();
        let return_to = form.previous_view.clone();
        
        let db = self.vault.db()?;
        let key = self.vault.dek()?;

        if let Some(id) = &form.editing_id {
            // Update existing credential
            let mut cred = crate::db::get_credential(db.conn(), id)?;
            cred.name = form.get_name().to_string();
            cred.credential_type = form.credential_type;
            cred.username = form.get_username();
            cred.url = form.get_url();
            cred.tags = form.get_tags();

            crate::vault::credential::update_credential(
                db.conn(),
                key,
                &mut cred,
                Some(form.get_secret()),
                form.get_notes().as_deref(),
            )?;

            self.log_audit(AuditAction::Update, Some(id), None)?;
            self.set_message("Credential updated", MessageType::Success);
        } else {
            // Create new credential
            let cred = crate::vault::credential::create_credential(
                db.conn(),
                key,
                form.get_name().to_string(),
                form.credential_type,
                form.get_secret(),
                form.get_username(),
                form.get_url(),
                form.get_tags(),
                form.get_notes().as_deref(),
            )?;

            self.log_audit(AuditAction::Create, Some(&cred.id), None)?;
            self.set_message("Credential created", MessageType::Success);
        }

        self.view = return_to;
        self.refresh_data()?;
        self.update_selected_detail()?;

        Ok(())
    }

    fn handle_text_input(&mut self, action: Action) -> Action {
        match action {
            Action::InsertChar(c) => {
                self.mode_state.insert_char(c);
                Action::None
            }
            Action::DeleteChar => {
                self.mode_state.delete_char();
                Action::None
            }
            Action::CursorLeft => {
                self.mode_state.cursor_left();
                Action::None
            }
            Action::CursorRight => {
                self.mode_state.cursor_right();
                Action::None
            }
            Action::CursorHome => {
                self.mode_state.cursor_home();
                Action::None
            }
            Action::CursorEnd => {
                self.mode_state.cursor_end();
                Action::None
            }
            Action::ClearLine => {
                self.mode_state.clear_buffer();
                Action::None
            }
            Action::Submit => {
                let buffer = self.mode_state.get_buffer().to_string();
                let result = match self.mode_state.mode {
                    InputMode::Command => Action::ExecuteCommand(buffer),
                    InputMode::Search => Action::Search(buffer),
                    InputMode::Filter => Action::Filter(buffer),
                    _ => Action::None,
                };
                self.mode_state.to_normal();
                result
            }
            Action::Cancel => {
                self.mode_state.to_normal();
                Action::None
            }
            _ => action,
        }
    }

    fn execute_action(&mut self, action: Action) -> Result<bool, Box<dyn std::error::Error>> {
        match action {
            Action::MoveUp => {
                self.list_state.move_up();
                self.update_selected_detail()?;
            }
            Action::MoveDown => {
                self.list_state.move_down();
                self.update_selected_detail()?;
            }
            Action::MoveToTop => {
                self.list_state.move_to_top();
                self.update_selected_detail()?;
            }
            Action::MoveToBottom => {
                self.list_state.move_to_bottom();
                self.update_selected_detail()?;
            }
            Action::PageUp => {
                self.list_state.page_up(10);
                self.update_selected_detail()?;
            }
            Action::PageDown => {
                self.list_state.page_down(10);
                self.update_selected_detail()?;
            }
            Action::HalfPageUp => {
                self.list_state.page_up(5);
                self.update_selected_detail()?;
            }
            Action::HalfPageDown => {
                self.list_state.page_down(5);
                self.update_selected_detail()?;
            }
            Action::ShowHelp => {
                self.help_state.home();
                self.mode_state.to_help();
            }
            Action::ChangePassword => {
                if self.vault.is_unlocked() {
                    self.wants_password_change = true;
                } else {
                    self.set_message("Vault must be unlocked", MessageType::Error);
                }
            }

            Action::Select => {
                if let Some(cred) = &self.selected_credential {
                    self.log_audit(AuditAction::Read, Some(&cred.id), None)?;
                }
                self.view = View::Detail;
            }
            Action::Back => {
                if self.view == View::Detail {
                    self.view = View::List;
                }
            }

            Action::CopyPassword => self.copy_secret()?,
            Action::CopyUsername => self.copy_username()?,
            Action::CopyTotp => self.copy_totp()?,
            Action::TogglePasswordVisibility => {
                self.password_visible = !self.password_visible;
                self.update_selected_detail()?;
            }

            Action::Delete => {
                if let Some(idx) = self.list_state.selected() {
                    if let Some(item) = self.credential_items.get(idx) {
                        self.pending_action = Some(PendingAction::DeleteCredential(item.id.clone()));
                        self.mode_state.to_confirm();
                    }
                }
            }

            Action::New => {
                self.credential_form = Some(CredentialForm::new());
                self.view = View::Form;
            }

            Action::Edit => {
                if let Some(ref cred) = self.selected_credential {
                    let form = CredentialForm::for_edit(
                        cred.id.clone(),
                        cred.name.clone(),
                        cred.credential_type,
                        cred.username.clone(),
                        cred.secret.as_ref().map(|s| s.expose_secret().to_string()).unwrap_or_default(),
                        cred.url.clone(),
                        cred.tags.clone(),
                        cred.notes.as_ref().map(|s| s.expose_secret().to_string()),
                        self.view.clone(),
                    );
                    self.credential_form = Some(form);
                    self.view = View::Form;
                } else if let Some(idx) = self.list_state.selected() {
                    // Need to decrypt first
                    if let Some(cred) = self.credentials.get(idx) {
                        let key = self.vault.dek()?;
                        let decrypted = crate::vault::credential::decrypt_credential(
                            self.vault.db()?.conn(),
                            key,
                            cred,
                            false,
                        )?;
                        let form = CredentialForm::for_edit(
                            decrypted.id.clone(),
                            decrypted.name.clone(),
                            decrypted.credential_type,
                            decrypted.username.clone(),
                            decrypted.secret.as_ref().map(|s| s.expose_secret().to_string()).unwrap_or_default(),
                            decrypted.url.clone(),
                            decrypted.tags.clone(),
                            decrypted.notes.as_ref().map(|s| s.expose_secret().to_string()),
                            self.view.clone(),
                        );
                        self.credential_form = Some(form);
                        self.view = View::Form;
                    }
                }
            }

            Action::EnterCommand => self.mode_state.to_command(),
            Action::EnterSearch => self.mode_state.to_search(),
            Action::EnterFilter => self.mode_state.to_filter(),

            Action::ExecuteCommand(cmd) => {
                let parsed = parse_command(&cmd);
                return self.execute_action(parsed);
            }
            Action::Search(query) => self.search_credentials(&query)?,
            Action::Filter(filter) => self.search_credentials(&filter)?,

            Action::GeneratePassword => {
                let password = crate::crypto::generate_password(&crate::crypto::PasswordPolicy::default());
                self.copy_to_clipboard(&password)?;
                self.set_message(&format!("Generated: {} (copied for {}s)", password, self.config.clipboard_timeout.as_secs()), MessageType::Success);
            }

            Action::Confirm => self.handle_confirm()?,
            Action::Cancel => {
                self.pending_action = None;
                self.mode_state.to_normal();
            }

            Action::Clear => {
                self.set_message("", MessageType::Info);
            }
            Action::Quit => {
                self.should_quit = true;
                return Ok(true);
            }
            Action::ForceQuit => {
                return Ok(true);
            }
            Action::Lock => self.lock(),
            Action::Refresh => self.refresh_data()?,
            Action::ShowLogs => {
                if self.vault.is_unlocked() {
                    match self.load_audit_logs() {
                        Ok(()) => {
                            self.mode_state.to_logs();
                        }
                        Err(e) => {
                            self.set_message(&format!("Failed to load logs: {}", e), MessageType::Error);
                        }
                    }
                } else {
                    self.set_message("Vault must be unlocked", MessageType::Error);
                }
            }
            Action::VerifyAudit => {
                match self.verify_audit_logs() {
                    Ok((0, total)) => {
                        self.set_message(
                            &format!("Audit OK: {} logs verified", total),
                            MessageType::Success,
                        );
                    }
                    Ok((tampered, total)) => {
                        self.set_message(
                            &format!("Warning: {} of {} logs may be tampered!", tampered, total),
                            MessageType::Error,
                        );
                    }
                    Err(e) => {
                        self.set_message(&format!("Audit check failed: {}", e), MessageType::Error);
                    }
                }
            }
            Action::Invalid(cmd) => {
                self.set_message(&format!("Unknown command: {}", cmd), MessageType::Error);
            }

            _ => {}
        }

        Ok(false)
    }

    /// Decrypt credential and store in self.selected_detail and self.selected_credential
    /// Previous values are dropped and zeroized via SecretString on each call
    fn update_selected_detail(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(idx) = self.list_state.selected() else {
            self.selected_detail = None;
            return Ok(());
        };

        let Some(cred) = self.credentials.get(idx) else {
            self.selected_detail = None;
            return Ok(());
        };

        let key = self.vault.dek()?;
        let decrypted = crate::vault::credential::decrypt_credential(
            self.vault.db()?.conn(),
            key,
            cred,
            false,
        )?;

        self.selected_detail = Some(self.build_detail(&decrypted));
        self.selected_credential = Some(decrypted);

        Ok(())
    }

    fn build_detail(&self, cred: &DecryptedCredential) -> CredentialDetail {
        let (totp_code, totp_remaining) = if cred.credential_type == CredentialType::Totp {
            if let Some(ref secret_str) = cred.secret {
                let totp_secret = serde_json::from_str::<TotpSecret>(secret_str.expose_secret())
                    .unwrap_or_else(|_| TotpSecret::new(
                        secret_str.expose_secret().to_string(),
                        cred.name.clone(),
                        "Vault-CLI".to_string(),
                    ));
                
                if let Ok(code) = totp::generate_totp(&totp_secret) {
                    let remaining = totp::time_remaining(&totp_secret);
                    (Some(code), Some(remaining))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        CredentialDetail {
            name: cred.name.clone(),
            credential_type: cred.credential_type,
            username: cred.username.clone(),
            secret: cred.secret.as_ref().map(|s| s.expose_secret().to_string()),
            secret_visible: self.password_visible,
            url: cred.url.clone(),
            notes: cred.notes.as_ref().map(|s| s.expose_secret().to_string()),
            tags: cred.tags.clone(),
            created_at: cred.created_at.format("%d-%b-%Y %H:%M").to_string(),
            updated_at: cred.updated_at.format("%d-%b-%Y %H:%M").to_string(),
            totp_code,
            totp_remaining,
        }
    }

    fn search_credentials(&mut self, query: &str) -> Result<(), Box<dyn std::error::Error>> {
        if query.is_empty() {
            self.refresh_data()?;
        } else {
            let db = self.vault.db()?;
            let results = crate::db::search_credentials(db.conn(), query)?;
            self.credential_items = results
                .iter()
                .map(|c| self.credential_to_item(c))
                .collect();
            self.credentials = results;
            self.list_state.set_total(self.credential_items.len());
        }
        Ok(())
    }

    fn copy_secret(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (secret, cred_id) = match &self.selected_credential {
            Some(cred) => match &cred.secret {
                Some(s) => (s.expose_secret().to_string(), cred.id.clone()),
                None => return Ok(()),
            },
            None => return Ok(()),
        };

        self.copy_to_clipboard(&secret)?;
        self.log_audit(AuditAction::Copy, Some(&cred_id), Some("secret"))?;
        self.set_message(&format!("Password copied ({}s)", self.config.clipboard_timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    fn copy_username(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (username, cred_id) = match &self.selected_credential {
            Some(cred) => match &cred.username {
                Some(u) => (u.clone(), cred.id.clone()),
                None => return Ok(()),
            },
            None => return Ok(()),
        };

        self.copy_to_clipboard(&username)?;
        self.log_audit(AuditAction::Copy, Some(&cred_id), Some("username"))?;
        self.set_message("Username copied", MessageType::Success);
        Ok(())
    }

    fn copy_totp(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Extract what we need before borrowing self mutably
        let (totp_secret, cred_id) = match &self.selected_credential {
            Some(cred) if cred.credential_type == CredentialType::Totp => {
                match &cred.secret {
                    Some(secret_str) => {
                        let secret = serde_json::from_str::<TotpSecret>(secret_str.expose_secret())
                            .unwrap_or_else(|_| TotpSecret::new(
                                secret_str.expose_secret().to_string(),
                                cred.name.clone(),
                                "Vault-CLI".to_string(),
                            ));
                        (secret, cred.id.clone())
                    }
                    None => return Ok(()),
                }
            }
            _ => return Ok(()),
        };

        let code = totp::generate_totp(&totp_secret)?;
        let remaining = totp::time_remaining(&totp_secret);
        self.copy_to_clipboard(&code)?;
        self.log_audit(AuditAction::Copy, Some(&cred_id), Some("totp"))?;
        self.set_message(&format!("TOTP: {} ({}s remaining)", code, remaining), MessageType::Success);
        Ok(())
    }

    fn copy_to_clipboard(&mut self, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let copy_id = CLIPBOARD_COPY_ID.fetch_add(1, Ordering::SeqCst) + 1;
        let mut text = text.to_string();
        let timeout = self.config.clipboard_timeout;

        std::thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                use std::process::{Command, Stdio};
                use std::io::Write;

                let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();

                let set_ok = if is_wayland {
                    Command::new("wl-copy")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .ok()
                        .and_then(|mut child| {
                            child.stdin.take()?.write_all(text.as_bytes()).ok()
                        })
                        .is_some()
                } else {
                    Command::new("xclip")
                        .args(["-selection", "clipboard"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .ok()
                        .and_then(|mut child| {
                            child.stdin.take()?.write_all(text.as_bytes()).ok()
                        })
                        .is_some()
                };

                if !set_ok {
                    return;
                }

                std::thread::sleep(timeout);

                // Zeroize local copy before thread exits
                text.zeroize();

                if CLIPBOARD_COPY_ID.load(Ordering::SeqCst) == copy_id {
                    if is_wayland {
                        let _ = Command::new("wl-copy").arg("--clear").output();
                    } else {
                        let _ = Command::new("xclip")
                            .args(["-selection", "clipboard"])
                            .stdin(Stdio::piped())
                            .output();
                    }
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                use arboard::Clipboard;

                let Ok(mut clipboard) = Clipboard::new() else {
                    return;
                };

                if clipboard.set_text(&text).is_err() {
                    return;
                }

                std::thread::sleep(timeout);

                if CLIPBOARD_COPY_ID.load(Ordering::SeqCst) == copy_id {
                    let _ = clipboard.clear();
                }
            }
        });

        Ok(())
    }

    fn handle_confirm(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(action) = self.pending_action.take() {
            match action {
                PendingAction::DeleteCredential(id) => {
                    let db = self.vault.db()?;
                    crate::db::delete_credential(db.conn(), &id)?;
                    self.log_audit(AuditAction::Delete, Some(&id), None)?;
                    self.refresh_data()?;
                    self.set_message("Credential deleted", MessageType::Success);
                }
                PendingAction::LockVault => {
                    self.lock();
                    self.set_message("Vault locked", MessageType::Info);
                }
                PendingAction::Quit => {
                    self.should_quit = true;
                }
            }
        }
        self.mode_state.to_normal();
        Ok(())
    }
}
