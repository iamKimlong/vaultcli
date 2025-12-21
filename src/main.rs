//! Vault-cli - Encrypted Credential Manager
//!
//! A local-first, vim-style TUI credential manager.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind },
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let vault_path = args.get(1).map(PathBuf::from);

    let mut config = AppConfig::default();
    if let Some(path) = vault_path {
        config.vault_path = path;
    }

    // Create parent directory
    if let Some(parent) = config.vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new(config);

    // Run app
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

    // Restore terminal
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
    let mut password = String::new();
    let mut confirm = String::new();
    let mut cursor = 0;
    let mut confirming = false;
    let mut error: Option<String> = None;

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let title = if confirming { " Confirm Password " } else { " Create Master Password " };
            let prompt = if confirming { "Confirm password:" } else { "Enter master password:" };
            let value = if confirming { &confirm } else { &password };
            
            let mut dialog = ui::PasswordDialog::new(title, prompt, value, cursor);
            if let Some(ref err) = error {
                dialog = dialog.error(err);
            }
            frame.render_widget(dialog, area);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => {
                        app.should_quit = true;
                        return Ok(());
                    }
                    KeyCode::Enter => {
                        if confirming {
                            if password == confirm {
                                if password.len() < 8 {
                                    error = Some("Password must be at least 8 characters".to_string());
                                    confirm.clear();
                                    cursor = 0;
                                } else {
                                    app.initialize(&password)?;
                                    return Ok(());
                                }
                            } else {
                                error = Some("Passwords do not match".to_string());
                                confirm.clear();
                                cursor = 0;
                            }
                        } else {
                            confirming = true;
                            cursor = 0;
                        }
                    }
                    KeyCode::Backspace => {
                        let target = if confirming { &mut confirm } else { &mut password };
                        if cursor > 0 {
                            cursor -= 1;
                            target.remove(cursor);
                        }
                    }
                    KeyCode::Char(c) => {
                        let target = if confirming { &mut confirm } else { &mut password };
                        target.insert(cursor, c);
                        cursor += 1;
                    }
                    KeyCode::Left if cursor > 0 => cursor -= 1,
                    KeyCode::Right => {
                        let len = if confirming { confirm.len() } else { password.len() };
                        if cursor < len { cursor += 1; }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn run_unlock(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut password = String::new();
    let mut cursor = 0;
    let mut error: Option<String> = None;
    let mut attempts = 0;

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let mut dialog = ui::PasswordDialog::new(
                " Unlock Vault ",
                "Enter master password:",
                &password,
                cursor,
            );
            if let Some(ref err) = error {
                dialog = dialog.error(err);
            }
            frame.render_widget(dialog, area);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => {
                        app.should_quit = true;
                        return Ok(());
                    }
                    KeyCode::Enter => {
                        match app.unlock(&password) {
                            Ok(()) => return Ok(()),
                            Err(_) => {
                                attempts += 1;
                                if attempts >= 5 {
                                    error = Some("Too many failed attempts".to_string());
                                    app.should_quit = true;
                                    return Ok(());
                                }
                                error = Some(format!("Invalid password ({}/5)", attempts));
                                password.clear();
                                cursor = 0;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        if cursor > 0 {
                            cursor -= 1;
                            password.remove(cursor);
                        }
                    }
                    KeyCode::Char(c) => {
                        password.insert(cursor, c);
                        cursor += 1;
                    }
                    KeyCode::Left if cursor > 0 => cursor -= 1,
                    KeyCode::Right if cursor < password.len() => cursor += 1,
                    _ => {}
                }
            }
        }
    }
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| {
            app.render(frame);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key)? {
                    break;
                }
            }
        }

        if app.should_quit {
            break;
        }

        // Check for auto-lock
        if app.vault.should_auto_lock() {
            app.lock();
            return run_unlock(terminal, app);
        }
    }

    Ok(())
}
