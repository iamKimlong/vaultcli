use crate::db::AuditAction;
use crate::input::keymap::{parse_command, Action};
use crate::ui::components::MessageType;
use crate::ui::renderer::View;

use super::config::PendingAction;
use super::App;

impl App {
    pub fn execute_action(&mut self, action: Action) -> Result<bool, Box<dyn std::error::Error>> {
        match action {
            Action::MoveUp => self.move_list(|ls| ls.move_up())?,
            Action::MoveDown => self.move_list(|ls| ls.move_down())?,
            Action::MoveToTop => self.move_list(|ls| ls.move_to_top())?,
            Action::MoveToBottom => self.move_list(|ls| ls.move_to_bottom())?,
            Action::PageUp => self.page_move(|ls, h| ls.page_up(h.saturating_sub(1)))?,
            Action::PageDown => self.page_move(|ls, h| ls.page_down(h.saturating_sub(1)))?,
            Action::HalfPageUp => self.page_move(|ls, h| ls.page_up(h / 2))?,
            Action::HalfPageDown => self.page_move(|ls, h| ls.page_down(h / 2))?,

            Action::ShowHelp => self.show_help(),
            Action::ShowTags => self.show_tags()?,
            Action::ShowLogs => self.show_logs()?,
            Action::ChangePassword => self.request_password_change(),

            Action::Select => self.select_credential()?,
            Action::Back => self.go_back()?,

            Action::CopyPassword => self.copy_secret()?,
            Action::CopyUsername => self.copy_username()?,
            Action::CopyTotp => self.copy_totp()?,
            Action::TogglePasswordVisibility => self.toggle_password()?,

            Action::Delete => self.initiate_delete(),
            Action::New => self.new_credential(),
            Action::Edit => self.edit_credential()?,

            Action::EnterCommand => self.mode_state.to_command(),
            Action::EnterSearch => self.mode_state.to_search(),

            Action::ExecuteCommand(cmd) => return self.execute_action(parse_command(&cmd)),
            Action::Search(query) => self.search_credentials(&query)?,
            Action::FilterByTag(tag) => self.filter_by_tag(&[tag])?,

            Action::GeneratePassword => self.generate_and_copy_password()?,

            Action::Confirm => self.handle_confirm()?,
            Action::Cancel => self.cancel_pending(),

            Action::Clear => self.set_message("", MessageType::Info),
            Action::Quit => return self.quit(),
            Action::ForceQuit => return Ok(true),
            Action::Lock => self.lock(),
            Action::Refresh => self.refresh_data()?,
            Action::VerifyAudit => self.verify_and_report_audit(),
            Action::Invalid(cmd) => self.set_message(&format!("Unknown command: {}", cmd), MessageType::Error),

            _ => {}
        }

        Ok(false)
    }

    fn move_list(&mut self, f: impl FnOnce(&mut crate::ui::components::ListViewState)) -> Result<(), Box<dyn std::error::Error>> {
        f(&mut self.list_state);
        self.update_selected_detail()
    }

    fn page_move(&mut self, f: impl FnOnce(&mut crate::ui::components::ListViewState, usize)) -> Result<(), Box<dyn std::error::Error>> {
        let visible = self.list_visible_height();
        f(&mut self.list_state, visible);
        self.update_selected_detail()
    }

    pub fn list_visible_height(&self) -> usize {
        (self.terminal_size.height as usize).saturating_sub(4)
    }

    fn show_help(&mut self) {
        self.help_state.home();
        self.help_state.scroll.pending_g = false;
        self.mode_state.to_help();
    }

    fn show_tags(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.vault.is_unlocked() {
            self.set_message("Vault must be unlocked", MessageType::Error);
            return Ok(());
        }
        self.load_tags()?;
        self.tags_state.scroll.pending_g = false;
        self.mode_state.to_tags();
        Ok(())
    }

    fn show_logs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.vault.is_unlocked() {
            self.set_message("Vault must be unlocked", MessageType::Error);
            return Ok(());
        }
        self.load_audit_logs()?;
        self.logs_state.scroll.pending_g = false;
        self.mode_state.to_logs();
        Ok(())
    }

    fn request_password_change(&mut self) {
        if self.vault.is_unlocked() {
            self.wants_password_change = true;
        } else {
            self.set_message("Vault must be unlocked", MessageType::Error);
        }
    }

    fn select_credential(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(cred) = &self.selected_credential {
            let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());
            self.log_audit(AuditAction::Read, Some(&id), Some(&name), username.as_deref(), None)?;
        }
        self.view = View::Detail;
        Ok(())
    }

    fn go_back(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.view == View::Detail {
            self.view = View::List;
        }
        self.search_credentials("")
    }

    fn toggle_password(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.password_visible = !self.password_visible;
        self.update_selected_detail()?;

        if let Some(cred) = &self.selected_credential {
            let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());
            self.log_audit(AuditAction::Read, Some(&id), Some(&name), username.as_deref(), Some("Toggle Password Visibility"))?;
        }
        Ok(())
    }

    fn initiate_delete(&mut self) {
        let Some(idx) = self.list_state.selected() else { return };
        let Some(item) = self.credential_items.get(idx) else { return };

        self.pending_action = Some(PendingAction::DeleteCredential(item.id.clone()));
        self.mode_state.to_confirm();
    }

    fn cancel_pending(&mut self) {
        self.pending_action = None;
        self.mode_state.to_normal();
    }

    fn handle_confirm(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(action) = self.pending_action.take() else {
            self.mode_state.to_normal();
            return Ok(());
        };

        match action {
            PendingAction::DeleteCredential(id) => self.delete_credential(&id)?,
            PendingAction::LockVault => self.confirm_lock(),
            PendingAction::Quit => self.should_quit = true,
        }

        self.mode_state.to_normal();
        Ok(())
    }

    fn confirm_lock(&mut self) {
        self.lock();
        self.set_message("Vault locked", MessageType::Info);
    }

    fn quit(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        self.should_quit = true;
        Ok(true)
    }

    fn verify_and_report_audit(&mut self) {
        let (msg, msg_type) = match self.verify_audit_logs() {
            Ok((0, total)) => (format!("Audit OK: {} logs verified", total), MessageType::Success),
            Ok((tampered, total)) => (format!("Warning: {} of {} logs may be tampered!", tampered, total), MessageType::Error),
            Err(e) => (format!("Audit check failed: {}", e), MessageType::Error),
        };
        self.set_message(&msg, msg_type);
    }
}
