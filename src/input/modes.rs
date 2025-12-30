//! Input Modes
//!
//! Modal editing state machine for vim-style interface.

/// Input mode enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal navigation mode
    Normal,
    /// Text input mode (insert)
    Insert,
    /// Command line mode (:)
    Command,
    /// Search mode (/)
    Search,
    /// Confirmation dialog
    Confirm,
    /// Help screen
    Help,
    /// Logs screen
    Logs,
    /// Tags screen
    Tags,
}

impl InputMode {
    /// Get mode indicator for status line
    pub fn indicator(&self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Insert => "INSERT",
            Self::Command => "COMMAND",
            Self::Search => "SEARCH",
            Self::Confirm => "CONFIRM",
            Self::Help => "HELP",
            Self::Logs => "LOG",
            Self::Tags => "TAG",
        }
    }

    /// Check if mode accepts text input
    pub fn is_text_input(&self) -> bool {
        matches!(self, Self::Insert | Self::Command | Self::Search)
    }
}

/// Mode state with associated data
#[derive(Debug, Clone)]
pub struct ModeState {
    /// Current mode
    pub mode: InputMode,
    /// Text buffer for input modes
    pub buffer: String,
    /// Cursor position in buffer
    pub cursor: usize,
    /// Pending key sequence (for multi-key commands like gg, dd)
    pub pending: Option<char>,
}

impl Default for ModeState {
    fn default() -> Self {
        Self {
            mode: InputMode::Normal,
            buffer: String::new(),
            cursor: 0,
            pending: None,
        }
    }
}

impl ModeState {
    /// Create new mode state
    pub fn new() -> Self {
        Self::default()
    }

    /// Switch to a new mode
    pub fn set_mode(&mut self, mode: InputMode) {
        self.mode = mode;
        self.buffer.clear();
        self.cursor = 0;
        self.pending = None;
    }

    /// Switch to normal mode
    pub fn to_normal(&mut self) {
        self.set_mode(InputMode::Normal);
    }

    /// Switch to insert mode
    pub fn to_insert(&mut self) {
        self.set_mode(InputMode::Insert);
    }

    /// Switch to command mode
    pub fn to_command(&mut self) {
        self.set_mode(InputMode::Command);
    }

    /// Switch to search mode
    pub fn to_search(&mut self) {
        self.set_mode(InputMode::Search);
    }

    /// Switch to confirm mode
    pub fn to_confirm(&mut self) {
        self.set_mode(InputMode::Confirm);
    }

    /// Switch to help mode
    pub fn to_help(&mut self) {
        self.set_mode(InputMode::Help);
    }

    /// Switch to tag mode
    pub fn to_tags(&mut self) {
        self.mode = InputMode::Tags;
    }

    /// Switch to log mode
    pub fn to_logs(&mut self) {
        self.mode = InputMode::Logs;
    }

    /// Insert character at cursor
    pub fn insert_char(&mut self, c: char) {
        self.buffer.insert(self.cursor, c);
        self.cursor += 1;
    }

    /// Delete character before cursor (backspace)
    pub fn delete_char(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.buffer.remove(self.cursor);
        }
    }

    /// Delete character at cursor (delete key)
    pub fn delete_char_forward(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
        }
    }

    /// Move cursor left
    pub fn cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// Move cursor right
    pub fn cursor_right(&mut self) {
        if self.cursor < self.buffer.len() {
            self.cursor += 1;
        }
    }

    /// Move cursor to start
    pub fn cursor_home(&mut self) {
        self.cursor = 0;
    }

    /// Move cursor to end
    pub fn cursor_end(&mut self) {
        self.cursor = self.buffer.len();
    }

    /// Clear buffer
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    /// Get buffer contents
    pub fn get_buffer(&self) -> &str {
        &self.buffer
    }

    /// Set buffer contents
    pub fn set_buffer(&mut self, content: &str) {
        self.buffer = content.to_string();
        self.cursor = self.buffer.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_transitions() {
        let mut state = ModeState::new();
        assert_eq!(state.mode, InputMode::Normal);

        state.to_insert();
        assert_eq!(state.mode, InputMode::Insert);

        state.to_command();
        assert_eq!(state.mode, InputMode::Command);

        state.to_normal();
        assert_eq!(state.mode, InputMode::Normal);
    }

    #[test]
    fn test_command_mode_input() {
        let mut state = ModeState::new();
        state.to_command();
        for c in "quit".chars() {
            state.insert_char(c);
        }
        assert_eq!(state.get_buffer(), "quit");
    }

    #[test]
    fn test_cancel_returns_to_normal() {
        let mut state = ModeState::new();
        state.to_command();
        state.insert_char('x');
        state.to_normal();
        assert_eq!(state.mode, InputMode::Normal);
    }

    #[test]
    fn test_text_input() {
        let mut state = ModeState::new();
        state.to_insert();

        state.insert_char('h');
        state.insert_char('e');
        state.insert_char('l');
        state.insert_char('l');
        state.insert_char('o');

        assert_eq!(state.get_buffer(), "hello");
        assert_eq!(state.cursor, 5);

        state.delete_char();
        assert_eq!(state.get_buffer(), "hell");
    }

    #[test]
    fn test_cursor_movement() {
        let mut state = ModeState::new();
        state.set_buffer("hello");

        state.cursor_home();
        assert_eq!(state.cursor, 0);

        state.cursor_end();
        assert_eq!(state.cursor, 5);

        state.cursor_left();
        assert_eq!(state.cursor, 4);

        state.cursor_right();
        assert_eq!(state.cursor, 5);
    }

    #[test]
    fn test_is_text_input() {
        assert!(!InputMode::Normal.is_text_input());
        assert!(InputMode::Insert.is_text_input());
        assert!(InputMode::Command.is_text_input());
        assert!(InputMode::Search.is_text_input());
        assert!(!InputMode::Help.is_text_input());
    }
}
