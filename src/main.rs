//! Vault - Encrypted Credential Manager
//!
//! A local-first, vim-style TUI credential manager.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use zeroize::Zeroize;

mod app;
mod crypto;
mod db;
mod input;
mod ui;
mod vault;

use app::{App, AppConfig};

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    harden_process();

    let config = parse_config();
    ensure_vault_dir(&config)?;

    let mut terminal = setup_terminal()?;
    let mut app = App::new(config);

    let result = run_with_auth(&mut terminal, &mut app);

    cleanup_terminal(&mut terminal)?;
    result
}

fn harden_process() {
    #[cfg(unix)]
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0); }
}

fn parse_config() -> AppConfig {
    let mut config = AppConfig::default();
    if let Some(path) = std::env::args().nth(1) {
        config.vault_path = PathBuf::from(path);
    }
    config
}

fn ensure_vault_dir(config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = config.vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn setup_terminal() -> Result<Term, Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn cleanup_terminal(terminal: &mut Term) -> Result<(), Box<dyn std::error::Error>> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_with_auth(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    if app.needs_init() {
        run_init(terminal, app)?;
    } else if app.is_locked() {
        run_unlock(terminal, app)?;
    }

    if !app.should_quit {
        run_app(terminal, app)?;
    }
    Ok(())
}

fn poll_key_press() -> Result<Option<KeyEvent>, Box<dyn std::error::Error>> {
    if !event::poll(Duration::from_millis(100))? {
        return Ok(None);
    }
    let Event::Key(key) = event::read()? else { return Ok(None) };
    if key.kind != KeyEventKind::Press { return Ok(None) }
    Ok(Some(key))
}

struct PasswordField {
    value: String,
    cursor: usize,
}

impl Default for PasswordField {
    fn default() -> Self {
        Self { value: String::new(), cursor: 0 }
    }
}

impl Drop for PasswordField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl PasswordField {
    fn clear(&mut self) {
        self.value.zeroize();
        self.cursor = 0;
    }
}

fn handle_password_key(field: &mut PasswordField, code: KeyCode) {
    match code {
        KeyCode::Backspace if field.cursor > 0 => password_backspace(field),
        KeyCode::Char(c) => password_insert(field, c),
        KeyCode::Left if field.cursor > 0 => field.cursor -= 1,
        KeyCode::Right if field.cursor < field.value.len() => field.cursor += 1,
        _ => {}
    }
}

fn password_backspace(field: &mut PasswordField) {
    field.cursor -= 1;
    field.value.remove(field.cursor);
}

fn password_insert(field: &mut PasswordField, c: char) {
    field.value.insert(field.cursor, c);
    field.cursor += 1;
}

fn draw_password_dialog(
    terminal: &mut Term,
    title: &str,
    prompt: &str,
    field: &PasswordField,
    error: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    terminal.draw(|frame| {
        let dialog = build_password_dialog(title, prompt, field, error);
        frame.render_widget(dialog, frame.area());
    })?;
    Ok(())
}

fn build_password_dialog<'a>(
    title: &'a str,
    prompt: &'a str,
    field: &'a PasswordField,
    error: Option<&'a str>,
) -> ui::PasswordDialog<'a> {
    let dialog = ui::PasswordDialog::new(title, prompt, &field.value, field.cursor);
    match error {
        Some(err) => dialog.error(err),
        None => dialog,
    }
}

fn run_init(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = InitState::default();

    while !state.done {
        init_iteration(terminal, app, &mut state)?;
    }
    Ok(())
}

#[derive(Default)]
struct InitState {
    password: PasswordField,
    confirm: PasswordField,
    confirming: bool,
    error: Option<String>,
    done: bool,
}

fn init_iteration(terminal: &mut Term, app: &mut App, state: &mut InitState) -> Result<(), Box<dyn std::error::Error>> {
    let (title, prompt, field) = init_dialog_params(state.confirming, &state.password, &state.confirm);
    draw_password_dialog(terminal, title, prompt, field, state.error.as_deref())?;

    let Some(key) = poll_key_press()? else { return Ok(()) };

    handle_init_key(key, state, app);
    Ok(())
}

fn init_dialog_params<'a>(
    confirming: bool,
    password: &'a PasswordField,
    confirm: &'a PasswordField,
) -> (&'static str, &'static str, &'a PasswordField) {
    if confirming {
        (" Confirm Password ", "Confirm password:", confirm)
    } else {
        (" Create Master Password ", "Enter master password:", password)
    }
}

fn handle_init_key(key: KeyEvent, state: &mut InitState, app: &mut App) {
    if key.code == KeyCode::Esc {
        app.should_quit = true;
        state.done = true;
        return;
    }

    if key.code == KeyCode::Enter {
        process_init_submit(state, app);
        return;
    }

    let field = if state.confirming { &mut state.confirm } else { &mut state.password };
    handle_password_key(field, key.code);
}

fn process_init_submit(state: &mut InitState, app: &mut App) {
    state.error = process_init_enter(state, app);
    state.done = state.error.is_none() && !state.confirming;
}

fn process_init_enter(state: &mut InitState, app: &mut App) -> Option<String> {
    if !state.confirming {
        return validate_init_password(&state.password, &mut state.confirming);
    }
    finalize_init(state, app)
}

fn validate_init_password(password: &PasswordField, confirming: &mut bool) -> Option<String> {
    if password.value.len() < 8 {
        return Some("Password must be at least 8 characters".into());
    }
    *confirming = true;
    None
}

fn finalize_init(state: &mut InitState, app: &mut App) -> Option<String> {
    if state.password.value != state.confirm.value {
        state.password.clear();
        state.confirm.clear();
        state.confirming = false;
        return Some("Passwords do not match".into());
    }

    if let Err(e) = app.initialize(&state.password.value) {
        state.confirm.clear();
        return Some(format!("Failed to initialize: {}", e));
    }

    state.confirming = false;
    None
}

fn run_unlock(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = UnlockState::default();

    while !state.done {
        unlock_iteration(terminal, app, &mut state)?;
    }
    Ok(())
}

#[derive(Default)]
struct UnlockState {
    password: PasswordField,
    error: Option<String>,
    attempts: u32,
    done: bool,
}

fn unlock_iteration(terminal: &mut Term, app: &mut App, state: &mut UnlockState) -> Result<(), Box<dyn std::error::Error>> {
    draw_password_dialog(terminal, " Unlock Vault ", "Enter master password:", &state.password, state.error.as_deref())?;

    let Some(key) = poll_key_press()? else { return Ok(()) };

    handle_unlock_key(key, state, app);
    Ok(())
}

fn handle_unlock_key(key: KeyEvent, state: &mut UnlockState, app: &mut App) {
    if key.code == KeyCode::Esc {
        app.should_quit = true;
        state.done = true;
        return;
    }

    if key.code == KeyCode::Enter {
        process_unlock_attempt(state, app);
        return;
    }

    handle_password_key(&mut state.password, key.code);
}

fn process_unlock_attempt(state: &mut UnlockState, app: &mut App) {
    if app.unlock(&state.password.value).is_ok() {
        state.done = true;
        return;
    }

    state.attempts += 1;
    state.password.clear();
    let _ = app.vault.record_failed_unlock();
    state.error = Some(format!("Invalid password ({}/5)", state.attempts));

    if state.attempts >= 5 {
        app.should_quit = true;
        state.done = true;
    }
}

struct PasswordChangeState {
    current: PasswordField,
    new_pass: PasswordField,
    confirm: PasswordField,
    step: u8,
    error: Option<String>,
}

impl Default for PasswordChangeState {
    fn default() -> Self {
        Self { current: PasswordField::default(), new_pass: PasswordField::default(), confirm: PasswordField::default(), step: 0, error: None }
    }
}

fn change_current_field(state: &mut PasswordChangeState) -> &mut PasswordField {
    match state.step {
        0 => &mut state.current,
        1 => &mut state.new_pass,
        _ => &mut state.confirm,
    }
}

fn change_prompt_and_field(state: &PasswordChangeState) -> (&'static str, &PasswordField) {
    match state.step {
        0 => ("Current password:", &state.current),
        1 => ("New password:", &state.new_pass),
        _ => ("Confirm new password:", &state.confirm),
    }
}

fn change_reset(state: &mut PasswordChangeState) {
    state.current.clear();
    state.new_pass.clear();
    state.confirm.clear();
    state.step = 0;
    state.error = None;
}

enum ChangeResult {
    Continue,
    Cancel,
    Success,
}

fn run_password_change(terminal: &mut Term, app: &mut App) -> Result<bool, Box<dyn std::error::Error>> {
    let mut state = PasswordChangeState::default();
    let mut result = ChangeResult::Continue;

    while matches!(result, ChangeResult::Continue) {
        result = change_iteration(terminal, app, &mut state)?;
    }

    Ok(matches!(result, ChangeResult::Success))
}

fn change_iteration(terminal: &mut Term, app: &mut App, state: &mut PasswordChangeState) -> Result<ChangeResult, Box<dyn std::error::Error>> {
    let (prompt, field) = change_prompt_and_field(state);
    draw_password_dialog(terminal, " Change Master Key ", prompt, field, state.error.as_deref())?;

    let Some(key) = poll_key_press()? else { return Ok(ChangeResult::Continue) };

    Ok(handle_change_key(key, state, &mut app.vault))
}

fn handle_change_key(key: KeyEvent, state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if key.code == KeyCode::Esc {
        return ChangeResult::Cancel;
    }

    if key.code == KeyCode::Enter {
        return process_change_step(state, vault);
    }

    handle_password_key(change_current_field(state), key.code);
    ChangeResult::Continue
}

fn process_change_step(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    match state.step {
        0 => process_change_verify(state, vault),
        1 => process_change_new(state),
        _ => process_change_confirm(state, vault),
    }
}

fn process_change_verify(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if let Err(e) = vault.verify_password(&state.current.value) {
        state.current.clear();
        state.error = Some(change_verify_error_msg(e));
        return ChangeResult::Continue;
    }
    state.step = 1;
    state.error = None;
    ChangeResult::Continue
}

fn change_verify_error_msg(e: vault::VaultError) -> String {
    match e {
        vault::VaultError::InvalidPassword => "Current password is incorrect",
        vault::VaultError::Locked => "Vault is locked",
        _ => "Verification failed",
    }.into()
}

fn process_change_new(state: &mut PasswordChangeState) -> ChangeResult {
    if state.new_pass.value.len() < 8 {
        state.new_pass.clear();
        state.error = Some("Password must be at least 8 characters".into());
        return ChangeResult::Continue;
    }

    if state.new_pass.value == state.current.value {
        state.new_pass.clear();
        state.error = Some("New password must be different".into());
        return ChangeResult::Continue;
    }

    state.step = 2;
    state.error = None;
    ChangeResult::Continue
}

fn process_change_confirm(state: &mut PasswordChangeState, vault: &mut vault::Vault) -> ChangeResult {
    if state.new_pass.value != state.confirm.value {
        state.confirm.clear();
        state.error = Some("Passwords do not match".into());
        return ChangeResult::Continue;
    }

    if let Err(e) = vault.change_password(&state.current.value, &state.new_pass.value) {
        state.error = Some(change_confirm_error_msg(e));
        change_reset(state);
        return ChangeResult::Continue;
    }

    ChangeResult::Success
}

fn change_confirm_error_msg(e: vault::VaultError) -> String {
    match e {
        vault::VaultError::InvalidPassword => "Current password is incorrect",
        _ => "Failed to change password",
    }.into()
}

fn run_app(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    while !app.should_quit && !app_iteration(terminal, app)? {}
    Ok(())
}

fn app_iteration(terminal: &mut Term, app: &mut App) -> Result<bool, Box<dyn std::error::Error>> {
    terminal.draw(|frame| app.render(frame))?;

    if process_app_input(terminal, app)? {
        return Ok(true);
    }

    check_auto_lock(terminal, app)?;
    Ok(false)
}

fn process_app_input(terminal: &mut Term, app: &mut App) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(key) = poll_key_press()? else { return Ok(false) };

    if app.handle_key_event(key)? {
        return Ok(true);
    }

    handle_password_change_request(terminal, app)?;
    Ok(false)
}

fn handle_password_change_request(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    if !app.wants_password_change {
        return Ok(());
    }

    app.wants_password_change = false;
    match run_password_change(terminal, app) {
        Ok(true) => app.set_message("Password changed successfully", ui::MessageType::Success),
        Ok(false) => {}
        Err(e) => app.set_message(&format!("Error: {}", e), ui::MessageType::Error),
    }
    Ok(())
}

fn check_auto_lock(terminal: &mut Term, app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    if app.vault.should_auto_lock() {
        app.lock();
    }

    while app.is_locked() && !app.should_quit {
        run_unlock(terminal, app)?;
    }
    Ok(())
}
