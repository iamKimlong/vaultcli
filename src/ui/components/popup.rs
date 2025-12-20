//! Popup Components
//!
//! Dialog boxes, input fields, and overlays.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
};

/// Centered rectangle helper
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Fixed size centered rectangle
pub fn centered_rect_fixed(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x + (r.width.saturating_sub(width)) / 2;
    let y = r.y + (r.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width.min(r.width), height.min(r.height))
}

/// Confirmation dialog
pub struct ConfirmDialog<'a> {
    title: &'a str,
    message: &'a str,
}

impl<'a> ConfirmDialog<'a> {
    pub fn new(title: &'a str, message: &'a str) -> Self {
        Self { title, message }
    }
}

impl<'a> Widget for ConfirmDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup_area = centered_rect_fixed(50, 7, area);
        
        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        // Message
        let msg = Paragraph::new(self.message)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        msg.render(Rect::new(inner.x, inner.y, inner.width, 2), buf);

        // Buttons hint
        let hint = Line::from(vec![
            Span::styled("[y]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" Yes  "),
            Span::styled("[n]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw(" No"),
        ]);
        buf.set_line(inner.x, inner.y + 3, &hint, inner.width);
    }
}

/// Message popup
pub struct MessagePopup<'a> {
    title: &'a str,
    message: &'a str,
    style: Style,
}

impl<'a> MessagePopup<'a> {
    pub fn info(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            style: Style::default().fg(Color::Cyan),
        }
    }

    pub fn error(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            style: Style::default().fg(Color::Red),
        }
    }

    pub fn success(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            style: Style::default().fg(Color::Green),
        }
    }
}

impl<'a> Widget for MessagePopup<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup_area = centered_rect_fixed(60, 5, area);
        
        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(self.style)
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let msg = Paragraph::new(self.message)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        msg.render(inner, buf);
    }
}

/// Text input field
pub struct InputField<'a> {
    label: &'a str,
    value: &'a str,
    cursor: usize,
    masked: bool,
}

impl<'a> InputField<'a> {
    pub fn new(label: &'a str, value: &'a str, cursor: usize) -> Self {
        Self {
            label,
            value,
            cursor,
            masked: false,
        }
    }

    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }
}

impl<'a> Widget for InputField<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Label
        buf.set_string(
            area.x,
            area.y,
            self.label,
            Style::default().fg(Color::Cyan),
        );

        // Input area
        let input_x = area.x;
        let input_y = area.y + 1;
        let input_width = area.width;

        // Background
        for x in input_x..input_x + input_width {
            if let Some(cell) = buf.cell_mut((x, input_y)) {
                cell.set_bg(Color::DarkGray);
            }
        }

        // Value (masked or plain)
        let display_value: String = if self.masked {
            "*".repeat(self.value.len())
        } else {
            self.value.to_string()
        };
        buf.set_string(input_x, input_y, &display_value, Style::default().fg(Color::White));

        // Cursor
        let cursor_x = input_x + self.cursor as u16;
        if cursor_x < input_x + input_width {
            if let Some(cell) = buf.cell_mut((cursor_x, input_y)) {
                cell.set_style(Style::default().bg(Color::White).fg(Color::Black));
            }
        }
    }
}

/// Password input dialog
pub struct PasswordDialog<'a> {
    title: &'a str,
    prompt: &'a str,
    value: &'a str,
    cursor: usize,
    error: Option<&'a str>,
}

impl<'a> PasswordDialog<'a> {
    pub fn new(title: &'a str, prompt: &'a str, value: &'a str, cursor: usize) -> Self {
        Self {
            title,
            prompt,
            value,
            cursor,
            error: None,
        }
    }

    pub fn error(mut self, err: &'a str) -> Self {
        self.error = Some(err);
        self
    }
}

impl<'a> Widget for PasswordDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let height = if self.error.is_some() { 9 } else { 7 };
        let popup_area = centered_rect_fixed(50, height, area);
        
        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        // Prompt
        buf.set_string(inner.x, inner.y, self.prompt, Style::default().fg(Color::White));

        // Input field
        let input_rect = Rect::new(inner.x, inner.y + 2, inner.width, 2);
        InputField::new("", self.value, self.cursor)
            .masked()
            .render(input_rect, buf);

        // Error message
        if let Some(err) = self.error {
            buf.set_string(
                inner.x,
                inner.y + 4,
                err,
                Style::default().fg(Color::Red),
            );
        }
    }
}

/// Help screen
pub struct HelpScreen;

impl Widget for HelpScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(80, 80, area);

        Clear.render(popup, buf);

        let block = help_block();
        let inner = block.inner(popup);

        block.render(popup, buf);

        render_help(inner, buf);
    }
}

fn help_block() -> Block<'static> {
    Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black))
}

fn render_help(inner: Rect, buf: &mut Buffer) {
    let mut y = inner.y;
    let max_y = inner.y + inner.height;

    for (section, bindings) in help_text() {
        if y >= max_y {
            break;
        }

        y = render_section_header(inner.x, y, section, buf);
        y = render_bindings(inner, y, max_y, bindings, buf);
        y += 1;
    }
}

fn render_section_header(x: u16, y: u16, title: &str, buf: &mut Buffer) -> u16 {
    buf.set_string(
        x,
        y,
        title,
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    y + 1
}

fn render_bindings(
    inner: Rect,
    mut y: u16,
    max_y: u16,
    bindings: Vec<(&str, &str)>,
    buf: &mut Buffer,
) -> u16 {
    for (key, desc) in bindings {
        if y >= max_y {
            break;
        }

        buf.set_string(inner.x + 2, y, key, Style::default().fg(Color::Cyan));
        buf.set_string(inner.x + 14, y, desc, Style::default().fg(Color::Gray));
        y += 1;
    }
    y
}

fn help_text() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("Navigation", vec![
            ("j / ↓", "Move down"),
            ("k / ↑", "Move up"),
            ("gg", "Go to top"),
            ("G", "Go to bottom"),
            ("Ctrl-d", "Half page down"),
            ("Ctrl-u", "Half page up"),
        ]),
        ("Actions", vec![
            ("l / Enter", "View details"),
            ("n", "New credential"),
            ("e", "Edit credential"),
            ("dd / x", "Delete credential"),
        ]),
        ("Clipboard", vec![
            ("yy / c", "Copy password"),
            ("u", "Copy username"),
            ("t", "Copy TOTP code"),
        ]),
        ("View", vec![
            ("s", "Toggle password visibility"),
            ("f", "Filter credentials"),
            ("/", "Search"),
        ]),
        ("Commands", vec![
            (":", "Command mode"),
            (":q", "Quit"),
            (":new", "New credential"),
            (":project", "New project"),
            (":gen", "Generate password"),
        ]),
        ("Other", vec![
            ("?", "Show this help"),
            ("L", "Lock vault"),
            ("q", "Quit"),
        ]),
    ]
}
