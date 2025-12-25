//! Keymap
//!
//! Vim-style key bindings mapped to actions.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Actions that can be triggered by key presses
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    // Navigation
    MoveUp,
    MoveDown,
    MoveToTop,
    MoveToBottom,
    PageUp,
    PageDown,
    HalfPageUp,
    HalfPageDown,

    // Selection
    Select,
    Back,

    // CRUD
    New,
    Edit,
    Delete,
    
    // Clipboard
    CopyPassword,
    CopyUsername,
    CopyTotp,

    // View
    TogglePasswordVisibility,
    ShowDetail,
    
    // Mode changes
    EnterCommand,
    EnterSearch,
    EnterFilter,
    ShowHelp,

    // Commands
    ExecuteCommand(String),
    Search(String),
    Filter(String),
    GeneratePassword,
    ChangePassword,
    
    // Confirmation
    Confirm,
    Cancel,

    // Application
    Clear,
    Quit,
    ForceQuit,
    Refresh,
    Lock,

    // Text input
    InsertChar(char),
    DeleteChar,
    DeleteCharForward,
    CursorLeft,
    CursorRight,
    CursorHome,
    CursorEnd,
    ClearLine,
    Submit,

    // No action
    None,
}

/// Map key event to action in normal mode
pub fn normal_mode_action(key: KeyEvent, pending: Option<char>) -> (Action, Option<char>) {
    match (key.code, key.modifiers, pending) {
        // Navigation
        (KeyCode::Char('j') | KeyCode::Down, _, _) => (Action::MoveDown, None),
        (KeyCode::Char('k') | KeyCode::Up, _, _) => (Action::MoveUp, None),
        (KeyCode::Char('g'), _, None) => (Action::None, Some('g')),
        (KeyCode::Char('g'), _, Some('g')) => (Action::MoveToTop, None),
        (KeyCode::Char('G'), _, _) => (Action::MoveToBottom, None),
        (KeyCode::Char('d'), KeyModifiers::CONTROL, _) => (Action::HalfPageDown, None),
        (KeyCode::Char('u'), KeyModifiers::CONTROL, _) => (Action::HalfPageUp, None),
        (KeyCode::PageDown, _, _) => (Action::PageDown, None),
        (KeyCode::PageUp, _, _) => (Action::PageUp, None),

        // Selection
        (KeyCode::Char('l'), KeyModifiers::CONTROL, _) => (Action::Clear, None),
        (KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right, _, _) => (Action::Select, None),
        (KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left, _, _) => (Action::Back, None),

        // CRUD
        (KeyCode::Char('n'), _, _) => (Action::New, None),
        (KeyCode::Char('e'), _, _) => (Action::Edit, None),
        (KeyCode::Char('d'), _, None) => (Action::None, Some('d')),
        (KeyCode::Char('d'), _, Some('d')) => (Action::Delete, None),
        (KeyCode::Char('x'), _, _) => (Action::Delete, None),

        // Clipboard
        (KeyCode::Char('c') | KeyCode::Char('y'), _, None) => (Action::None, Some('y')),
        (KeyCode::Char('y'), _, Some('y')) => (Action::CopyPassword, None),
        (KeyCode::Char('c'), _, Some('y')) => (Action::CopyPassword, None),
        (KeyCode::Char('u'), _, None) => (Action::CopyUsername, None),
        (KeyCode::Char('t'), _, _) => (Action::CopyTotp, None),

        // View
        (KeyCode::Char('s'), _, _) => (Action::TogglePasswordVisibility, None),

        // Mode changes
        (KeyCode::Char(':'), _, _) => (Action::EnterCommand, None),
        (KeyCode::Char('/'), _, _) => (Action::EnterSearch, None),
        (KeyCode::Char('f'), _, _) => (Action::EnterFilter, None),
        (KeyCode::Char('?'), _, _) => (Action::ShowHelp, None),

        // Application
        (KeyCode::Char('q'), _, _) => (Action::Quit, None),
        (KeyCode::Char('Q'), _, _) => (Action::ForceQuit, None),
        (KeyCode::Char('r'), KeyModifiers::CONTROL, _) => (Action::Refresh, None),
        (KeyCode::Char('p'), KeyModifiers::CONTROL, _) => (Action::ChangePassword, None),
        (KeyCode::Char('L'), _, _) => (Action::Lock, None),

        _ => (Action::None, None),
    }
}

/// Map key event to action in text input modes
pub fn text_input_action(key: KeyEvent) -> Action {
    match (key.code, key.modifiers) {
        (KeyCode::Esc, _) => Action::Cancel,
        (KeyCode::Enter, _) => Action::Submit,
        (KeyCode::Backspace, _) => Action::DeleteChar,
        (KeyCode::Delete, _) => Action::DeleteCharForward,
        (KeyCode::Left, _) => Action::CursorLeft,
        (KeyCode::Right, _) => Action::CursorRight,
        (KeyCode::Home, _) | (KeyCode::Char('a'), KeyModifiers::CONTROL) => Action::CursorHome,
        (KeyCode::End, _) | (KeyCode::Char('e'), KeyModifiers::CONTROL) => Action::CursorEnd,
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => Action::ClearLine,
        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => Action::InsertChar(c),
        _ => Action::None,
    }
}

/// Map key event to action in confirm mode
pub fn confirm_action(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => Action::Confirm,
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Action::Cancel,
        _ => Action::None,
    }
}

/// Map key event to action in help mode
pub fn help_action(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => Action::Back,
        KeyCode::Char('j') | KeyCode::Down => Action::MoveDown,
        KeyCode::Char('k') | KeyCode::Up => Action::MoveUp,
        _ => Action::None,
    }
}

/// Parse command string into action
pub fn parse_command(cmd: &str) -> Action {
    let cmd = cmd.trim();
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let command = parts[0];
    let _args = parts.get(1).copied();

    match command {
        "cls" | "clear" => Action::Clear,
        "q" | "quit" => Action::Quit,
        "q!" | "quit!" => Action::ForceQuit,
        "w" | "write" => Action::None, // Auto-save, no action needed
        "wq" => Action::Quit,
        "new" | "n" => Action::New,
        "edit" | "e" => Action::Edit,
        "delete" | "del" => Action::Delete,
        "gen" | "generate" => Action::GeneratePassword,
        "help" | "h" => Action::ShowHelp,
        "passwd" | "password" | "changepw" => Action::ChangePassword,
        "lock" => Action::Lock,
        "refresh" => Action::Refresh,
        _ => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn key_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn test_normal_navigation() {
        assert_eq!(normal_mode_action(key(KeyCode::Char('j')), None).0, Action::MoveDown);
        assert_eq!(normal_mode_action(key(KeyCode::Char('k')), None).0, Action::MoveUp);
        assert_eq!(normal_mode_action(key(KeyCode::Char('G')), None).0, Action::MoveToBottom);
    }

    #[test]
    fn test_gg_sequence() {
        let (action1, pending1) = normal_mode_action(key(KeyCode::Char('g')), None);
        assert_eq!(action1, Action::None);
        assert_eq!(pending1, Some('g'));

        let (action2, pending2) = normal_mode_action(key(KeyCode::Char('g')), pending1);
        assert_eq!(action2, Action::MoveToTop);
        assert_eq!(pending2, None);
    }

    #[test]
    fn test_dd_sequence() {
        let (action1, pending1) = normal_mode_action(key(KeyCode::Char('d')), None);
        assert_eq!(action1, Action::None);
        assert_eq!(pending1, Some('d'));

        let (action2, pending2) = normal_mode_action(key(KeyCode::Char('d')), pending1);
        assert_eq!(action2, Action::Delete);
        assert_eq!(pending2, None);
    }

    #[test]
    fn test_text_input() {
        assert_eq!(text_input_action(key(KeyCode::Char('a'))), Action::InsertChar('a'));
        assert_eq!(text_input_action(key(KeyCode::Backspace)), Action::DeleteChar);
        assert_eq!(text_input_action(key(KeyCode::Enter)), Action::Submit);
        assert_eq!(text_input_action(key(KeyCode::Esc)), Action::Cancel);
    }

    #[test]
    fn test_ctrl_shortcuts() {
        assert_eq!(text_input_action(key_ctrl(KeyCode::Char('a'))), Action::CursorHome);
        assert_eq!(text_input_action(key_ctrl(KeyCode::Char('e'))), Action::CursorEnd);
        assert_eq!(text_input_action(key_ctrl(KeyCode::Char('u'))), Action::ClearLine);
    }

    #[test]
    fn test_parse_command() {
        assert_eq!(parse_command("q"), Action::Quit);
        assert_eq!(parse_command("quit"), Action::Quit);
        assert_eq!(parse_command("q!"), Action::ForceQuit);
        assert_eq!(parse_command("new"), Action::New);
        assert_eq!(parse_command("help"), Action::ShowHelp);
    }

    #[test]
    fn test_confirm_action() {
        assert_eq!(confirm_action(key(KeyCode::Char('y'))), Action::Confirm);
        assert_eq!(confirm_action(key(KeyCode::Char('n'))), Action::Cancel);
        assert_eq!(confirm_action(key(KeyCode::Enter)), Action::Confirm);
        assert_eq!(confirm_action(key(KeyCode::Esc)), Action::Cancel);
    }
}
