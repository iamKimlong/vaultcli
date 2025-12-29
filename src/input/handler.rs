//! Input Handler
//!
//! Processes input events and dispatches to appropriate handlers.

use crossterm::event::KeyEvent;

use super::keymap::{
    confirm_action, help_action, normal_mode_action, text_input_action, Action,
};
use super::modes::{InputMode, ModeState};

/// Input handler that processes key events based on current mode
pub struct InputHandler;

impl InputHandler {
    /// Process a key event and return the resulting action
    pub fn handle_key_event(key: KeyEvent, state: &mut ModeState) -> Action {
        match state.mode {
            InputMode::Normal => {
                let (action, new_pending) = normal_mode_action(key, state.pending);
                state.pending = new_pending;
                action
            }
            InputMode::Insert | InputMode::Command | InputMode::Search => {
                let action = text_input_action(key);
                match &action {
                    Action::InsertChar(c) => {
                        state.insert_char(*c);
                        Action::None // Character already processed
                    }
                    Action::DeleteChar => {
                        state.delete_char();
                        Action::None
                    }
                    Action::DeleteCharForward => {
                        state.delete_char_forward();
                        Action::None
                    }
                    Action::CursorLeft => {
                        state.cursor_left();
                        Action::None
                    }
                    Action::CursorRight => {
                        state.cursor_right();
                        Action::None
                    }
                    Action::CursorHome => {
                        state.cursor_home();
                        Action::None
                    }
                    Action::CursorEnd => {
                        state.cursor_end();
                        Action::None
                    }
                    Action::ClearLine => {
                        state.clear_buffer();
                        Action::None
                    }
                    Action::Submit => {
                        let buffer = state.get_buffer().to_string();
                        let result = match state.mode {
                            InputMode::Command => Action::ExecuteCommand(buffer),
                            InputMode::Search => Action::Search(buffer),
                            _ => Action::Submit,
                        };
                        state.to_normal();
                        result
                    }
                    Action::Cancel => {
                        state.to_normal();
                        Action::Cancel
                    }
                    _ => action,
                }
            }
            InputMode::Confirm => confirm_action(key),
            InputMode::Help => help_action(key),
            InputMode::Logs => Action::None,
            InputMode::Tags => Action::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn test_normal_mode() {
        let mut state = ModeState::new();
        
        let action = InputHandler::handle_key_event(key(KeyCode::Char('j')), &mut state);
        assert_eq!(action, Action::MoveDown);
    }

    #[test]
    fn test_command_mode_input() {
        let mut state = ModeState::new();
        state.to_command();

        // Type "quit"
        InputHandler::handle_key_event(key(KeyCode::Char('q')), &mut state);
        InputHandler::handle_key_event(key(KeyCode::Char('u')), &mut state);
        InputHandler::handle_key_event(key(KeyCode::Char('i')), &mut state);
        InputHandler::handle_key_event(key(KeyCode::Char('t')), &mut state);

        assert_eq!(state.get_buffer(), "quit");

        let action = InputHandler::handle_key_event(key(KeyCode::Enter), &mut state);
        assert_eq!(action, Action::ExecuteCommand("quit".to_string()));
        assert_eq!(state.mode, InputMode::Normal);
    }

    #[test]
    fn test_search_mode() {
        let mut state = ModeState::new();
        state.to_search();

        InputHandler::handle_key_event(key(KeyCode::Char('t')), &mut state);
        InputHandler::handle_key_event(key(KeyCode::Char('e')), &mut state);
        InputHandler::handle_key_event(key(KeyCode::Char('s')), &mut state);
        InputHandler::handle_key_event(key(KeyCode::Char('t')), &mut state);

        let action = InputHandler::handle_key_event(key(KeyCode::Enter), &mut state);
        assert_eq!(action, Action::Search("test".to_string()));
    }

    #[test]
    fn test_cancel_returns_to_normal() {
        let mut state = ModeState::new();
        state.to_command();
        state.insert_char('x');

        let action = InputHandler::handle_key_event(key(KeyCode::Esc), &mut state);
        assert_eq!(action, Action::Cancel);
        assert_eq!(state.mode, InputMode::Normal);
    }

    #[test]
    fn test_confirm_mode() {
        let mut state = ModeState::new();
        state.to_confirm();

        let action = InputHandler::handle_key_event(key(KeyCode::Char('y')), &mut state);
        assert_eq!(action, Action::Confirm);
    }
}
