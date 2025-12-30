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
            Self::Info => Color::Blue,
            Self::Success => Color::Green,
            Self::Warning => Color::Yellow,
            Self::Error => Color::Red,
        }
    }
}

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

fn mode_style(mode: InputMode) -> Style {
    let base = Style::default().fg(Color::Black);
    match mode {
        InputMode::Normal => base.bg(Color::Blue),
        InputMode::Insert => base.bg(Color::Green),
        InputMode::Command => base.bg(Color::Red),
        InputMode::Search => base.bg(Color::Magenta),
        InputMode::Confirm => base.bg(Color::Red),
        InputMode::Help => base.bg(Color::Yellow),
        InputMode::Logs => base.bg(Color::Green),
        InputMode::Tags => base.bg(Color::Magenta),
    }
}

fn command_prefix(mode: InputMode) -> &'static str {
    match mode {
        InputMode::Command => ":",
        InputMode::Search => "/",
        _ => "",
    }
}

fn render_mode_indicator(buf: &mut Buffer, area: Rect, mode: InputMode) -> u16 {
    let style = mode_style(mode).add_modifier(Modifier::BOLD);
    let mode_text = format!(" {} ", mode.indicator());
    buf.set_string(area.x, area.y, &mode_text, style);
    mode_text.len() as u16
}

fn render_command_or_message(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    mode: InputMode,
    command_buffer: Option<&str>,
    message: Option<(&str, MessageType)>,
) {
    let style_base = Style::default().bg(Color::DarkGray);

    if let Some(buffer) = command_buffer {
        let cmd_text = format!("{}{}", command_prefix(mode), buffer);
        buf.set_string(x, y, &cmd_text, style_base.fg(Color::White));
        return;
    }

    if let Some((msg, msg_type)) = message {
        buf.set_string(x, y, msg, style_base.fg(msg_type.color()));
    }
}

fn build_right_text(item_count: Option<(usize, usize)>, vault_name: Option<&str>) -> String {
    let mut right_parts: Vec<String> = Vec::new();

    if let Some((selected, total)) = item_count {
        right_parts.push(format!("{}/{}", selected + 1, total));
    }

    if let Some(vault) = vault_name {
        right_parts.push(vault.to_string());
    }

    right_parts.join(" ")
}

fn render_right_section(buf: &mut Buffer, area: Rect, right_text: &str) {
    let right_x = area.x + area.width.saturating_sub(right_text.len() as u16 + 1);
    let style = Style::default().fg(Color::Gray).bg(Color::DarkGray);
    buf.set_string(right_x, area.y, right_text, style);
}

impl<'a> Widget for StatusLine<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, Style::default().bg(Color::DarkGray));

        let mode_width = render_mode_indicator(buf, area, self.mode);
        let x = area.x + mode_width;

        buf.set_string(x, area.y, " ", Style::default().bg(Color::DarkGray));
        let x = x + 1;

        render_command_or_message(buf, x, area.y, self.mode, self.command_buffer, self.message);

        let right_text = build_right_text(self.item_count, self.vault_name);
        render_right_section(buf, area, &right_text);
    }
}

pub struct HelpBar<'a> {
    hints: Vec<(&'a str, &'a str)>,
}

impl<'a> HelpBar<'a> {
    pub fn new(hints: Vec<(&'a str, &'a str)>) -> Self {
        Self { hints }
    }

    pub fn for_mode(mode: InputMode) -> Self {
        Self { hints: hints_for_mode(mode) }
    }
}

fn hints_for_mode(mode: InputMode) -> Vec<(&'static str, &'static str)> {
    match mode {
        InputMode::Normal => vec![
            ("L", "lock vault"),
            ("i", "logs"),
            ("t", "tags"),
            ("/", "search"),
            (":", "command"),
            ("?", "help"),
        ],
        InputMode::Insert => vec![
            ("Esc", "cancel"),
            ("Enter", "confirm"),
            ("C-u", "clear"),
        ],
        InputMode::Command | InputMode::Search => vec![
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
        InputMode::Logs | InputMode::Tags => vec![
            ("j/k", "scroll"),
            ("Ctrl-d/u", "page"),
            ("q", "close"),
        ],
    }
}

fn build_hint_spans<'a>(hints: &[(&'a str, &'a str)]) -> Vec<Span<'a>> {
    let mut spans: Vec<Span> = Vec::new();

    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(*key, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {}", desc), Style::default().fg(Color::Gray)));
    }

    spans
}

impl<'a> Widget for HelpBar<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let spans = build_hint_spans(&self.hints);
        let line = Line::from(spans);
        buf.set_line(area.x, area.y, &line, area.width);
    }
}
