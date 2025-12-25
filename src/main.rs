//! Vault-cli - Encrypted Credential Manager
//!
//! A local-first, vim-style TUI credential manager.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod app;
mod crypto;
mod db;
mod input;
mod ui;
mod vault;

use app::{App, AppConfig};

struct PasswordField {
    value: String,
    cursor: usize,
}

impl PasswordField {
    fn new() -> Self {
        Self { value: String::new(), cursor: 0 }
    }

    fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    fn handle_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                self.value.remove(self.cursor);
            }
            KeyCode::Char(c) => {
                self.value.insert(self.cursor, c);
                self.cursor += 1;
            }
            KeyCode::Left if self.cursor > 0 => self.cursor -= 1,
            KeyCode::Right if self.cursor < self.value.len() => self.cursor += 1,
            _ => {}
        }
    }
}

fn poll_key_press() -> Result<Option<KeyEvent>, Box<dyn std::error::Error>> {
    if !event::poll(Duration::from_millis(100))? {
        return Ok(None);
    }
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => Ok(Some(key)),
        _ => Ok(None),
    }
}

fn draw_password_dialog(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    title: &str,
    prompt: &str,
    field: &PasswordField,
    error: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    terminal.draw(|frame| {
        let mut dialog = ui::PasswordDialog::new(title, prompt, &field.value, field.cursor);
        if let Some(err) = error {
            dialog = dialog.error(err);
        }
        frame.render_widget(dialog, frame.area());
    })?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config = AppConfig::default();
    if let Some(path) = args.get(1) {
        config.vault_path = PathBuf::from(path);
    }

    if let Some(parent) = config.vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config);

    let result = if app.needs_init() {
        run_init(&mut terminal, &mut app)
    } else if app.is_locked() {
        run_unlock(&mut terminal, &mut app)
    } else {
        Ok(())
    };

    if result.is_ok() && !app.should_quit {
        let _ = run_app(&mut terminal, &mut app);
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn run_init(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut password = PasswordField::new();
    let mut confirm = PasswordField::new();
    let mut confirming = false;
    let mut error: Option<String> = None;

    loop {
        let (title, prompt, field) = if confirming {
            (" Confirm Password ", "Confirm password:", &confirm)
        } else {
            (" Create Master Password ", "Enter master password:", &password)
        };
        draw_password_dialog(terminal, title, prompt, field, error.as_deref())?;

        let Some(key) = poll_key_press()? else { continue };

        match key.code {
            KeyCode::Esc => {
                app.should_quit = true;
                return Ok(());
            }
            KeyCode::Enter => {
                match handle_init_enter(&mut password, &mut confirm, &mut confirming, app) {
                    InitResult::Continue(err) => {
                        error = err;
                    }
                    InitResult::Done => return Ok(()),
                }
            }
            code => {
                if confirming { &mut confirm } else { &mut password }.handle_key(code);
            }
        }
    }
}

enum InitResult {
    Continue(Option<String>),
    Done,
}

fn handle_init_enter(
    password: &mut PasswordField,
    confirm: &mut PasswordField,
    confirming: &mut bool,
    app: &mut App,
) -> InitResult {
    if !*confirming {
        if password.value.len() < 8 {
            return InitResult::Continue(Some("Password must be at least 8 characters".into()));
        }
        *confirming = true;
        return InitResult::Continue(None);
    }

    if password.value != confirm.value {
        password.clear();
        confirm.clear();
        *confirming = false;
        return InitResult::Continue(Some("Passwords do not match".into()));
    }

    match app.initialize(&password.value) {
        Ok(()) => InitResult::Done,
        Err(e) => {
            confirm.clear();
            InitResult::Continue(Some(format!("Failed to initialize: {}", e)))
        }
    }
}

fn run_unlock(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut password = PasswordField::new();
    let mut error: Option<String> = None;
    let mut attempts = 0;

    loop {
        draw_password_dialog(
            terminal,
            " Unlock Vault ",
            "Enter master password:",
            &password,
            error.as_deref(),
        )?;

        let Some(key) = poll_key_press()? else { continue };

        match key.code {
            KeyCode::Esc => {
                app.should_quit = true;
                return Ok(());
            }
            KeyCode::Enter => {
                match app.unlock(&password.value) {
                    Ok(()) => return Ok(()),
                    Err(_) => {
                        attempts += 1;
                        password.clear();
                        if attempts >= 5 {
                            app.should_quit = true;
                            return Ok(());
                        }
                        error = Some(format!("Invalid password ({}/5)", attempts));
                    }
                }
            }
            code => password.handle_key(code),
        }
    }
}

#[derive(Default)]
struct PasswordChangeState {
    current: PasswordField,
    new_pass: PasswordField,
    confirm: PasswordField,
    step: u8,
    error: Option<String>,
}

impl Default for PasswordField {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordChangeState {
    fn current_field(&mut self) -> &mut PasswordField {
        match self.step {
            0 => &mut self.current,
            1 => &mut self.new_pass,
            _ => &mut self.confirm,
        }
    }

    fn prompt(&self) -> (&'static str, &PasswordField) {
        match self.step {
            0 => ("Current password:", &self.current),
            1 => ("New password:", &self.new_pass),
            _ => ("Confirm new password:", &self.confirm),
        }
    }

    fn reset(&mut self) {
        self.current.clear();
        self.new_pass.clear();
        self.confirm.clear();
        self.step = 0;
        self.error = None;
    }
}

enum ChangeResult {
    Continue,
    Cancel,
    Success,
}

fn run_password_change(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut state = PasswordChangeState::default();

    loop {
        let (prompt, field) = state.prompt();
        draw_password_dialog(
            terminal,
            " Change Master Key ",
            prompt,
            field,
            state.error.as_deref(),
        )?;

        let Some(key) = poll_key_press()? else { continue };

        match key.code {
            KeyCode::Esc => return Ok(false),
            KeyCode::Enter => {
                match handle_change_enter(&mut state, &mut app.vault) {
                    ChangeResult::Continue => {}
                    ChangeResult::Cancel => return Ok(false),
                    ChangeResult::Success => return Ok(true),
                }
            }
            code => state.current_field().handle_key(code),
        }
    }
}

fn handle_change_enter(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    match state.step {
        0 => {
            if let Err(e) = vault.verify_password(&state.current.value) {
                state.current.clear();
                state.error = Some(match e {
                    vault::VaultError::InvalidPassword => "Current password is incorrect".into(),
                    vault::VaultError::Locked => "Vault is locked".into(),
                    _ => "Verification failed".into(),
                });
                return ChangeResult::Continue;
            }
            state.step = 1;
            state.error = None;
            ChangeResult::Continue
        }
        1 => {
            if state.new_pass.value.len() < 8 {
                state.new_pass.clear();
                state.error = Some("Password must be at least 8 characters".into());
            } else if state.new_pass.value == state.current.value {
                state.new_pass.clear();
                state.error = Some("New password must be different".into());
            } else {
                state.step = 2;
                state.error = None;
            }
            ChangeResult::Continue
        }
        _ => handle_change_confirm(state, vault),
    }
}

fn handle_change_confirm(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if state.new_pass.value != state.confirm.value {
        state.confirm.clear();
        state.error = Some("Passwords do not match".into());
        return ChangeResult::Continue;
    }

    match vault.change_password(&state.current.value, &state.new_pass.value) {
        Ok(()) => ChangeResult::Success,
        Err(e) => {
            state.error = Some(match e {
                vault::VaultError::InvalidPassword => "Current password is incorrect".into(),
                _ => "Failed to change password".into(),
            });
            state.reset();
            ChangeResult::Continue
        }
    }
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| app.render(frame))?;

        if let Some(key) = poll_key_press()? {
            if app.handle_key(key)? {
                break;
            }

            if app.wants_password_change {
                app.wants_password_change = false;
                match run_password_change(terminal, app) {
                    Ok(true) => app.set_message("Password changed successfully", ui::MessageType::Success),
                    Ok(false) => {}
                    Err(e) => app.set_message(&format!("Error: {}", e), ui::MessageType::Error),
                }
            }
        }

        if app.should_quit {
            break;
        }

        if app.vault.should_auto_lock() {
            app.lock();
        }

        if app.is_locked() {
            while app.is_locked() && !app.should_quit {
                run_unlock(terminal, app)?;
            }
            continue; // resume main loop after unlocking
        }
    }

    Ok(())
}
