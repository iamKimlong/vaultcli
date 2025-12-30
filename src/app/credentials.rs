use secrecy::ExposeSecret;

use crate::crypto::totp::{self, TotpSecret};
use crate::db::models::{Credential, CredentialType};
use crate::db::AuditAction;
use crate::ui::components::{CredentialDetail, CredentialForm, CredentialItem, MessageType};
use crate::ui::renderer::View;
use crate::vault::credential::DecryptedCredential;

use super::App;

impl App {
    pub fn refresh_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        self.credentials = crate::db::get_all_credentials(db.conn())?;
        self.credential_items = self.credentials.iter().map(|c| credential_to_item(c)).collect();
        self.list_state.set_total(self.credential_items.len());
        Ok(())
    }

    pub fn clear_credentials(&mut self) {
        self.credentials.clear();
        self.credential_items.clear();
        self.selected_credential = None;
        self.selected_detail = None;
    }

    pub fn search_credentials(&mut self, query: &str) -> Result<(), Box<dyn std::error::Error>> {
        if query.is_empty() {
            self.refresh_data()?;
            return self.update_selected_detail();
        }

        let db = self.vault.db()?;
        let results = crate::db::search_credentials(db.conn(), query)?;
        self.credential_items = results.iter().map(|c| credential_to_item(c)).collect();
        self.credentials = results;
        self.list_state.set_total(self.credential_items.len());
        self.update_selected_detail()
    }

    pub fn filter_by_tag(&mut self, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let results = crate::db::get_credentials_by_tag(db.conn(), tags)?;
        self.credential_items = results.iter().map(|c| credential_to_item(c)).collect();
        self.credentials = results;
        self.list_state.set_total(self.credential_items.len());

        let msg = match tags.len() {
            1 => format!("Filtered by tag: {}", tags[0]),
            _ => format!("Filtered by tags: {}", tags.join(" ")),
        };
        self.set_message(&msg, MessageType::Info);
        self.update_selected_detail()
    }

    pub fn update_selected_detail(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(idx) = self.list_state.selected() else {
            self.selected_detail = None;
            return Ok(());
        };
        let Some(cred) = self.credentials.get(idx) else {
            self.selected_detail = None;
            return Ok(());
        };

        let key = self.vault.dek()?;
        let db = self.vault.db()?;
        let decrypted = crate::vault::credential::decrypt_credential(db.conn(), key, cred, false)?;

        self.selected_detail = Some(build_detail(&decrypted, self.password_visible));
        self.selected_credential = Some(decrypted);
        Ok(())
    }

    pub fn new_credential(&mut self) {
        self.credential_form = Some(CredentialForm::new());
        self.view = View::Form;
    }

    pub fn edit_credential(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(cred) = self.selected_credential.clone() {
            self.open_edit_form(&cred);
            return Ok(());
        }

        let Some(idx) = self.list_state.selected() else {
            return Ok(());
        };
        let Some(cred) = self.credentials.get(idx) else {
            return Ok(());
        };

        let key = self.vault.dek()?;
        let db = self.vault.db()?;
        let decrypted = crate::vault::credential::decrypt_credential(db.conn(), key, cred, false)?;
        self.open_edit_form(&decrypted);
        Ok(())
    }

    fn open_edit_form(&mut self, cred: &DecryptedCredential) {
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
    }

    pub fn save_credential_form(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let form = self.credential_form.take().unwrap();
        let return_to = form.previous_view.clone();
        let editing_id = form.editing_id.clone();

        match editing_id {
            Some(id) => self.do_update_credential(&form, &id)?,
            None => self.do_create_credential(&form)?,
        }

        self.view = return_to;
        self.refresh_data()?;
        self.update_selected_detail()
    }

    fn do_update_credential(&mut self, form: &CredentialForm, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let key = self.vault.dek()?;

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

        self.log_audit(AuditAction::Update, Some(id), Some(&cred.name), cred.username.as_deref(), None)?;
        self.set_message("Credential updated", MessageType::Success);
        Ok(())
    }

    fn do_create_credential(&mut self, form: &CredentialForm) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let key = self.vault.dek()?;

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

        self.log_audit(AuditAction::Create, Some(&cred.id), Some(&cred.name), cred.username.as_deref(), None)?;
        self.set_message("Credential created", MessageType::Success);
        Ok(())
    }

    pub fn delete_credential(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.vault.db()?;
        let cred = crate::db::get_credential(db.conn(), id)?;
        crate::db::delete_credential(db.conn(), id)?;
        self.log_audit(AuditAction::Delete, Some(id), Some(&cred.name), cred.username.as_deref(), None)?;
        self.refresh_data()?;
        self.set_message("Credential deleted", MessageType::Success);
        Ok(())
    }

    pub fn copy_secret(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        let Some(secret) = &cred.secret else { return Ok(()) };

        let text = secret.expose_secret().to_string();
        let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&text, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), username.as_deref(), Some("Secret"))?;
        self.set_message(&format!("Password copied ({}s)", self.config.clipboard_timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    pub fn copy_username(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        let Some(username) = &cred.username else { return Ok(()) };

        let text = username.clone();
        let (id, name, u) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&text, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), u.as_deref(), Some("Username"))?;
        self.set_message(&format!("Username copied ({}s)", self.config.clipboard_timeout.as_secs()), MessageType::Success);
        Ok(())
    }

    pub fn copy_totp(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cred) = &self.selected_credential else { return Ok(()) };
        if cred.credential_type != CredentialType::Totp {
            return Ok(());
        }
        let Some(secret_str) = &cred.secret else { return Ok(()) };

        let totp_secret = parse_totp_secret(secret_str.expose_secret(), &cred.name);
        let code = totp::generate_totp(&totp_secret)?;
        let remaining = totp::time_remaining(&totp_secret);
        let (id, name, username) = (cred.id.clone(), cred.name.clone(), cred.username.clone());

        super::clipboard::copy_with_timeout(&code, self.config.clipboard_timeout);
        self.log_audit(AuditAction::Copy, Some(&id), Some(&name), username.as_deref(), Some("TOTP"))?;
        self.set_message(&format!("TOTP: {} ({}s remaining)", code, remaining), MessageType::Success);
        Ok(())
    }

    pub fn generate_and_copy_password(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let password = crate::crypto::generate_password(&crate::crypto::PasswordPolicy::default());
        super::clipboard::copy_with_timeout(&password, self.config.clipboard_timeout);
        self.set_message(
            &format!("Generated: {} (copied for {}s)", password, self.config.clipboard_timeout.as_secs()),
            MessageType::Success,
        );
        Ok(())
    }
}

pub fn credential_to_item(cred: &Credential) -> CredentialItem {
    CredentialItem {
        id: cred.id.clone(),
        name: cred.name.clone(),
        username: cred.username.clone(),
        credential_type: cred.credential_type,
        tags: cred.tags.clone(),
    }
}

pub fn build_detail(cred: &DecryptedCredential, password_visible: bool) -> CredentialDetail {
    let (totp_code, totp_remaining) = compute_totp(cred);

    CredentialDetail {
        name: cred.name.clone(),
        credential_type: cred.credential_type,
        username: cred.username.clone(),
        secret: cred.secret.as_ref().map(|s| s.expose_secret().to_string()),
        secret_visible: password_visible,
        url: cred.url.clone(),
        notes: cred.notes.as_ref().map(|s| s.expose_secret().to_string()),
        tags: cred.tags.clone(),
        created_at: cred.created_at.format("%d-%b-%Y at %H:%M").to_string(),
        updated_at: cred.updated_at.format("%d-%b-%Y at %H:%M").to_string(),
        totp_code,
        totp_remaining,
    }
}

fn compute_totp(cred: &DecryptedCredential) -> (Option<String>, Option<u64>) {
    if cred.credential_type != CredentialType::Totp {
        return (None, None);
    }
    let Some(ref secret_str) = cred.secret else {
        return (None, None);
    };

    let totp_secret = parse_totp_secret(secret_str.expose_secret(), &cred.name);

    totp::generate_totp(&totp_secret)
        .ok()
        .map(|code| (Some(code), Some(totp::time_remaining(&totp_secret))))
        .unwrap_or((None, None))
}

fn parse_totp_secret(secret: &str, name: &str) -> TotpSecret {
    serde_json::from_str::<TotpSecret>(secret)
        .unwrap_or_else(|_| TotpSecret::new(secret.to_string(), name.to_string(), "Vault".to_string()))
}
