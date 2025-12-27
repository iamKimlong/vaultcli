//! Status Line Component
//!
//! Displays mode indicator, messages, and vault info.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Widget,
};

use crate::input::InputMode;

/// Message type for status line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Info,
    Success,
    Warning,
    Error,
}

impl MessageType {
    pub fn color(&self) -> Color {
        match self {
            Self::Info => Color::White,
            Self::Success => Color::Green,
            Self::Warning => Color::Yellow,
            Self::Error => Color::Red,
        }
    }
}

/// Status line widget
pub struct StatusLine<'a> {
    mode: InputMode,
    command_buffer: Option<&'a str>,
    message: Option<(&'a str, MessageType)>,
    vault_name: Option<&'a str>,
    item_count: Option<(usize, usize)>,
}

impl<'a> StatusLine<'a> {
    pub fn new(mode: InputMode) -> Self {
        Self {
            mode,
            command_buffer: None,
            message: None,
            vault_name: None,
            item_count: None,
        }
    }

    pub fn command_buffer(mut self, buffer: &'a str) -> Self {
        self.command_buffer = Some(buffer);
        self
    }

    pub fn message(mut self, msg: &'a str, msg_type: MessageType) -> Self {
        self.message = Some((msg, msg_type));
        self
    }

    pub fn vault_name(mut self, name: &'a str) -> Self {
        self.vault_name = Some(name);
        self
    }

    pub fn item_count(mut self, selected: usize, total: usize) -> Self {
        self.item_count = Some((selected, total));
        self
    }
}

impl<'a> Widget for StatusLine<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, Style::default().bg(Color::DarkGray));

        let mut x = area.x;

        // Mode indicator
        let mode_style = match self.mode {
            InputMode::Normal => Style::default().fg(Color::Black).bg(Color::Blue),
            InputMode::Insert => Style::default().fg(Color::Black).bg(Color::Green),
            InputMode::Command => Style::default().fg(Color::Black).bg(Color::Red),
            InputMode::Search => Style::default().fg(Color::Black).bg(Color::Magenta),
            InputMode::Filter => Style::default().fg(Color::Black).bg(Color::Cyan),
            InputMode::Confirm => Style::default().fg(Color::Black).bg(Color::Red),
            InputMode::Help => Style::default().fg(Color::Black).bg(Color::Yellow),
        };

        let mode_text = format!(" {} ", self.mode.indicator());
        buf.set_string(x, area.y, &mode_text, mode_style.add_modifier(Modifier::BOLD));
        x += mode_text.len() as u16;

        buf.set_string(x, area.y, " ", Style::default().bg(Color::DarkGray));
        x += 1;

        if let Some(buffer) = self.command_buffer {
            let prefix = match self.mode {
                InputMode::Command => ":",
                InputMode::Search => "/",
                InputMode::Filter => "filter: ",
                _ => "",
            };
            let cmd_text = format!("{}{}", prefix, buffer);
            buf.set_string(x, area.y, &cmd_text, Style::default().fg(Color::White).bg(Color::DarkGray));
        } else if let Some((msg, msg_type)) = self.message {
            buf.set_string(x, area.y, msg, Style::default().fg(msg_type.color()).bg(Color::DarkGray));
        }

        let mut right_parts: Vec<String> = Vec::new();
        if let Some((selected, total)) = self.item_count {
            right_parts.push(format!("{}/{}", selected + 1, total));
        }
        if let Some(vault) = self.vault_name {
            right_parts.push(vault.to_string());
        }

        let right_text = right_parts.join(" ");
        let right_x = area.x + area.width.saturating_sub(right_text.len() as u16 + 1);
        buf.set_string(right_x, area.y, &right_text, Style::default().fg(Color::Gray).bg(Color::DarkGray));
    }
}

/// Help bar widget
pub struct HelpBar<'a> {
    hints: Vec<(&'a str, &'a str)>,
}

impl<'a> HelpBar<'a> {
    pub fn new(hints: Vec<(&'a str, &'a str)>) -> Self {
        Self { hints }
    }

    pub fn for_mode(mode: InputMode) -> Self {
        let hints = match mode {
            InputMode::Normal => vec![
                ("j/k", "navigate"),
                ("n", "new"),
                ("Enter", "select"),
                ("yy", "yank"),
                ("dd", "delete"),
                ("/", "search"),
                (":", "command"),
                ("?", "help"),
            ],
            InputMode::Insert => vec![
                ("Esc", "cancel"),
                ("Enter", "confirm"),
                ("C-u", "clear"),
            ],
            InputMode::Command | InputMode::Search | InputMode::Filter => vec![
                ("Esc", "cancel"),
                ("Enter", "execute"),
            ],
            InputMode::Confirm => vec![
                ("y", "yes"),
                ("n", "no"),
            ],
            InputMode::Help => vec![
                ("q", "close"),
                ("j/k", "scroll"),
            ],
        };
        Self { hints }
    }
}

impl<'a> Widget for HelpBar<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut spans: Vec<Span> = Vec::new();
        for (i, (key, desc)) in self.hints.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
            }
            spans.push(Span::styled(*key, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
            spans.push(Span::styled(format!(" {}", desc), Style::default().fg(Color::Gray)));
        }
        let line = Line::from(spans);
        buf.set_line(area.x, area.y, &line, area.width);
    }
}
