//! Popup Components
//!
//! Dialog boxes, input fields, and overlays.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Clear, Paragraph, Widget, Wrap},
};
use crate::db::AuditLog;

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

impl Widget for ConfirmDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup_area = centered_rect_fixed(50, 7, area);

        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let msg = Paragraph::new(self.message)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        msg.render(Rect::new(inner.x, inner.y, inner.width, 2), buf);

        let hint = Line::from(vec![
            Span::styled(
                "[y]",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Yes  "),
            Span::styled(
                "[n]",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
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
            style: Style::default().fg(Color::Magenta),
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

impl Widget for MessagePopup<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup_area = centered_rect_fixed(60, 5, area);

        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
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

impl Widget for InputField<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_string(area.x, area.y, self.label, Style::default().fg(Color::Cyan));

        let input_x = area.x;
        let input_y = area.y + 1;
        let input_width = area.width;

        for x in input_x..input_x + input_width {
            if let Some(cell) = buf.cell_mut((x, input_y)) {
                cell.set_bg(Color::DarkGray);
            }
        }

        let display_value: String = if self.masked {
            "*".repeat(self.value.len())
        } else {
            self.value.to_string()
        };
        buf.set_string(
            input_x,
            input_y,
            &display_value,
            Style::default().fg(Color::White),
        );

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

impl Widget for PasswordDialog<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let height = if self.error.is_some() { 7 } else { 6 };
        let popup_area = centered_rect_fixed(50, height, area);

        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        buf.set_string(
            inner.x,
            inner.y,
            self.prompt,
            Style::default().fg(Color::White),
        );

        let input_rect = Rect::new(inner.x, inner.y + 1, inner.width, 2);
        InputField::new("", self.value, self.cursor)
            .masked()
            .render(input_rect, buf);

        if let Some(err) = self.error {
            buf.set_string(inner.x, inner.y + 3, err, Style::default().fg(Color::Red));
        }
    }
}

const TWO_COLUMN_MIN_WIDTH: u16 = 80;
const COLUMN_WIDTH: u16 = 38;

/// Scrollable help screen state
#[derive(Default)]
pub struct HelpState {
    pub scroll: usize,
}

impl HelpState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max_scroll: usize) {
        self.scroll = (self.scroll + amount).min(max_scroll);
    }

    pub fn home(&mut self) {
        self.scroll = 0;
    }

    pub fn end(&mut self, max_scroll: usize) {
        self.scroll = max_scroll;
    }
}

/// Help screen widget
pub struct HelpScreen<'a> {
    state: &'a HelpState,
}

impl<'a> HelpScreen<'a> {
    pub fn new(state: &'a HelpState) -> Self {
        Self { state }
    }

    /// Calculate total content height for scrolling bounds
    pub fn content_height() -> usize {
        help_sections()
            .iter()
            .map(|(_, bindings)| 1 + bindings.len() + 1) // header + bindings + spacing
            .sum::<usize>()
            .saturating_sub(1) // no trailing space after last section
    }

    /// Calculate max scroll value given visible height
    pub fn max_scroll(visible_height: u16) -> usize {
        Self::content_height().saturating_sub(visible_height as usize)
    }
}

impl Widget for HelpScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(65, 65, area);
        Clear.render(popup, buf);

        let block = Block::default()
            .title(" Help Page ")
            .title_bottom(Line::from(" j/k scroll • q close ").centered())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup);
        block.render(popup, buf);

        let use_two_columns = inner.width >= TWO_COLUMN_MIN_WIDTH;

        if use_two_columns {
            render_two_columns(inner, buf, self.state.scroll);
        } else {
            render_single_column(inner, buf, self.state.scroll);
        }
    }
}

fn render_single_column(area: Rect, buf: &mut Buffer, scroll: usize) {
    let sections = help_sections();
    let lines = build_help_lines(&sections);

    for (i, line) in lines.iter().enumerate().skip(scroll) {
        let y = area.y + (i - scroll) as u16;
        if y >= area.y + area.height {
            break;
        }
        render_help_line(area.x, y, area.width, line, buf);
    }
}

fn render_two_columns(area: Rect, buf: &mut Buffer, scroll: usize) {
    let sections = help_sections();
    let (left_sections, right_sections) = split_sections_for_columns(&sections);

    let left_lines = build_help_lines(&left_sections);
    let right_lines = build_help_lines(&right_sections);

    let gap = 4u16;
    let col_width = (area.width.saturating_sub(gap)) / 2;
    let right_x = area.x + col_width + gap;

    let max_lines = left_lines.len().max(right_lines.len());

    for i in scroll..max_lines {
        let y = area.y + (i - scroll) as u16;
        if y >= area.y + area.height {
            break;
        }

        if let Some(line) = left_lines.get(i) {
            render_help_line(area.x, y, col_width, line, buf);
        }
        if let Some(line) = right_lines.get(i) {
            render_help_line(right_x, y, col_width, line, buf);
        }
    }
}

enum HelpLine<'a> {
    Header(&'a str),
    Binding(&'a str, &'a str),
    Empty,
}

fn build_help_lines<'a>(sections: &'a [(&'a str, Vec<(&'a str, &'a str)>)]) -> Vec<HelpLine<'a>> {
    let mut lines = Vec::new();

    for (i, (header, bindings)) in sections.iter().enumerate() {
        lines.push(HelpLine::Header(header));
        for (key, desc) in bindings {
            lines.push(HelpLine::Binding(key, desc));
        }
        if i < sections.len() - 1 {
            lines.push(HelpLine::Empty);
        }
    }

    lines
}

fn render_help_line(x: u16, y: u16, width: u16, line: &HelpLine, buf: &mut Buffer) {
    match line {
        HelpLine::Header(title) => {
            buf.set_string(
                x,
                y,
                *title,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        }
        HelpLine::Binding(key, desc) => {
            buf.set_string(x + 2, y, *key, Style::default().fg(Color::Cyan));
            let desc_x = x + 14;
            let desc_width = width.saturating_sub(14) as usize;
            let truncated: String = desc.chars().take(desc_width).collect();
            buf.set_string(desc_x, y, &truncated, Style::default().fg(Color::Gray));
        }
        HelpLine::Empty => {}
    }
}

fn split_sections_for_columns<'a>(
    sections: &'a [(&'a str, Vec<(&'a str, &'a str)>)],
) -> (
    Vec<(&'a str, Vec<(&'a str, &'a str)>)>,
    Vec<(&'a str, Vec<(&'a str, &'a str)>)>,
) {
    let total_lines: usize = sections
        .iter()
        .map(|(_, b)| 1 + b.len() + 1)
        .sum();
    let target = total_lines / 2;

    let mut left = Vec::new();
    let mut right = Vec::new();
    let mut current_lines = 0;

    for section in sections {
        let section_lines = 1 + section.1.len() + 1;
        if current_lines < target {
            left.push((section.0, section.1.clone()));
        } else {
            right.push((section.0, section.1.clone()));
        }
        current_lines += section_lines;
    }

    (left, right)
}

fn help_sections() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        (
            "Navigation",
            vec![
                ("j / ↓", "Move down"),
                ("k / ↑", "Move up"),
                ("gg", "Go to top"),
                ("G", "Go to bottom"),
                ("Ctrl-d", "Half page down"),
                ("Ctrl-u", "Half page up"),
            ],
        ),
        (
            "Actions",
            vec![
                ("l / Enter", "View details"),
                ("n", "New credential"),
                ("e", "Edit credential"),
                ("dd / x", "Delete credential"),
            ],
        ),
        (
            "Clipboard",
            vec![
                ("yy / c", "Copy password/secret"),
                ("u", "Copy username"),
                ("t", "Copy TOTP code"),
            ],
        ),
        (
            "View",
            vec![
                ("s", "Toggle password"),
                ("f", "Filter credentials"),
                ("/", "Search"),
            ],
        ),
        (
            "Commands",
            vec![
                (":", "Command mode"),
                (":q", "Quit"),
                (":clear", "Clear message"),
                (":changepw", "Change master key"),
                (":audit", "Verify audit log integrity"),
                (":log", "View logs"),
                (":new", "New credential"),
                (":gen", "Generate password"),
            ],
        ),
        (
            "Other",
            vec![
                ("?", "Show this help"),
                ("Ctrl-l", "Clear message"),
                ("Ctrl-p", "Change master key"),
                ("L", "Lock vault"),
                ("i", "View logs"),
                ("q", "Quit"),
            ],
        ),
    ]
}

/// Scrollable logs screen state
#[derive(Default)]
pub struct LogsState {
    pub scroll: usize,
    pub logs: Vec<AuditLog>,
}

impl LogsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_logs(&mut self, logs: Vec<AuditLog>) {
        self.logs = logs;
        self.scroll = 0; // Reset scroll when logs update
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max_scroll: usize) {
        self.scroll = (self.scroll + amount).min(max_scroll);
    }

    pub fn home(&mut self) {
        self.scroll = 0;
    }

    pub fn end(&mut self, max_scroll: usize) {
        self.scroll = max_scroll;
    }

    pub fn max_scroll(&self, visible_height: u16) -> usize {
        self.logs.len().saturating_sub(visible_height as usize)
    }
}

/// Audit logs screen widget
pub struct LogsScreen<'a> {
    state: &'a LogsState,
}

impl<'a> LogsScreen<'a> {
    pub fn new(state: &'a LogsState) -> Self {
        Self { state }
    }
}

impl Widget for LogsScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(75, 70, area);
        Clear.render(popup, buf);

        let block = Block::default()
            .title(" Audit Logs ")
            .title_bottom(Line::from(" j/k scroll • Ctrl-d/u page • q close ").centered())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup);
        block.render(popup, buf);

        if self.state.logs.is_empty() {
            let msg = Paragraph::new("No audit logs found")
                .style(Style::default().fg(Color::DarkGray));
            msg.render(inner, buf);
            return;
        }

        // Render header
        let header_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
        let header = format!(
            "{:<19}  {:<8}  {:<36}  {}",
            "TIMESTAMP", "ACTION", "CREDENTIAL", "DETAILS"
        );
        buf.set_string(inner.x, inner.y, &header, header_style);

        // Render separator
        let sep: String = "─".repeat(inner.width as usize);
        buf.set_string(inner.x, inner.y + 1, &sep, Style::default().fg(Color::DarkGray));

        // Render log entries
        let content_start_y = inner.y + 2;
        let visible_height = inner.height.saturating_sub(2) as usize;

        for (i, log) in self.state.logs.iter().enumerate().skip(self.state.scroll) {
            let row_idx = i - self.state.scroll;
            if row_idx >= visible_height {
                break;
            }

            let y = content_start_y + row_idx as u16;
            render_log_row(inner.x, y, inner.width, log, buf);
        }
    }
}

fn render_log_row(x: u16, y: u16, width: u16, log: &AuditLog, buf: &mut Buffer) {
    // Format timestamp: "28-Dec-2025 14:30"
    let timestamp = log.timestamp.format("%d-%b-%Y %H:%M").to_string();

    // Action with color coding
    let (action_str, action_color) = match log.action {
        crate::db::AuditAction::Create => ("CREATE", Color::Green),
        crate::db::AuditAction::Read => ("READ", Color::Blue),
        crate::db::AuditAction::Update => ("UPDATE", Color::Yellow),
        crate::db::AuditAction::Delete => ("DELETE", Color::Red),
        crate::db::AuditAction::Copy => ("COPY", Color::Magenta),
        crate::db::AuditAction::Export => ("EXPORT", Color::Cyan),
        crate::db::AuditAction::Import => ("IMPORT", Color::Cyan),
        crate::db::AuditAction::Unlock => ("UNLOCK", Color::Green),
        crate::db::AuditAction::Lock => ("LOCK", Color::Yellow),
    };

    // Credential ID (truncated)
    let cred_id = log.credential_id.as_deref().unwrap_or("-");
    let cred_display: String = if cred_id.len() > 36 {
        format!("{}...", &cred_id[..33])
    } else {
        cred_id.to_string()
    };

    // Details (truncated to fit)
    let details = log.details.as_deref().unwrap_or("-");
    let remaining_width = width.saturating_sub(19 + 2 + 8 + 2 + 36 + 2) as usize;
    let details_display: String = if details.len() > remaining_width {
        format!("{}...", &details[..remaining_width.saturating_sub(3)])
    } else {
        details.to_string()
    };

    // Render each column
    buf.set_string(x, y, &timestamp, Style::default().fg(Color::Gray));
    buf.set_string(x + 21, y, action_str, Style::default().fg(action_color));
    buf.set_string(x + 31, y, &cred_display, Style::default().fg(Color::White));
    buf.set_string(x + 69, y, &details_display, Style::default().fg(Color::White));
}
