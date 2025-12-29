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
use crate::db::{AuditLog, Credential};

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

/// Generic scrollable popup state with both vertical and horizontal scrolling
#[derive(Default, Clone)]
pub struct ScrollState {
    pub v_scroll: usize,
    pub h_scroll: usize,
    pub pending_g: bool,
}

impl ScrollState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.v_scroll = 0;
        self.h_scroll = 0;
        self.pending_g = false;
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.v_scroll = self.v_scroll.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        self.v_scroll = (self.v_scroll + amount).min(max);
    }

    pub fn scroll_left(&mut self, amount: usize) {
        self.h_scroll = self.h_scroll.saturating_sub(amount);
    }

    pub fn scroll_right(&mut self, amount: usize, max: usize) {
        self.h_scroll = (self.h_scroll + amount).min(max);
    }

    pub fn home(&mut self) {
        self.v_scroll = 0;
    }

    pub fn end(&mut self, max: usize) {
        self.v_scroll = max;
    }

    pub fn h_home(&mut self) {
        self.h_scroll = 0;
    }

    pub fn h_end(&mut self, max: usize) {
        self.h_scroll = max;
    }
}

/// Tags popup state
#[derive(Default)]
pub struct TagsState {
    pub scroll: ScrollState,
    pub tags: Vec<(String, usize)>, // (tag_name, count)
    pub selected: usize,
    pub selected_tags: std::collections::HashSet<String>,
}

impl TagsState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set tags from credentials - aggregates and counts
    pub fn set_tags_from_credentials(&mut self, credentials: &[Credential]) {
        use std::collections::HashMap;
        
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        for cred in credentials {
            for tag in &cred.tags {
                *tag_counts.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        let mut tags: Vec<_> = tag_counts.into_iter().collect();
        tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))); // Sort by count desc, then name
        
        self.tags = tags;
        self.scroll.reset();
        self.selected = 0;
        self.selected_tags.clear();
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        if self.selected < self.tags.len().saturating_sub(1) {
            self.selected += 1;
        }
    }

    pub fn page_up(&mut self, amount: usize) {
        self.selected = self.selected.saturating_sub(amount);
    }

    pub fn page_down(&mut self, amount: usize) {
        self.selected = (self.selected + amount).min(self.tags.len().saturating_sub(1));
    }

    pub fn home(&mut self) {
        self.selected = 0;
    }

    pub fn end(&mut self) {
        self.selected = self.tags.len().saturating_sub(1);
    }

    pub fn selected_tag(&self) -> Option<&str> {
        self.tags.get(self.selected).map(|(t, _)| t.as_str())
    }

    pub fn toggle_selected(&mut self) {
        if let Some((tag, _)) = self.tags.get(self.selected) {
            if self.selected_tags.contains(tag) {
                self.selected_tags.remove(tag);
            } else {
                self.selected_tags.insert(tag.clone());
            }
        }
    }

    pub fn get_selected_tags(&self) -> Vec<String> {
        self.selected_tags.iter().cloned().collect()
    }

    pub fn has_selection(&self) -> bool {
        !self.selected_tags.is_empty()
    }

    /// Calculate max scroll given visible height
    pub fn max_scroll(&self, visible_height: u16) -> usize {
        self.tags.len().saturating_sub(visible_height as usize)
    }
}

/// Tags popup widget
pub struct TagsPopup<'a> {
    state: &'a TagsState,
}

impl<'a> TagsPopup<'a> {
    pub fn new(state: &'a TagsState) -> Self {
        Self { state }
    }

    /// Calculate visible height for the tags popup
    pub fn visible_height(area: Rect) -> u16 {
        let popup = centered_rect_fixed(50, 20, area);
        popup.height.saturating_sub(4) // borders + header + separator
    }
}

impl Widget for TagsPopup<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let height = (self.state.tags.len() as u16 + 4).min(20).max(8);
        let popup = centered_rect_fixed(55, height, area);

        Clear.render(popup, buf);

        let block = Block::default()
            .title(" Tags ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup);
        block.render(popup, buf);

        if self.state.tags.is_empty() {
            let msg = Paragraph::new("No tags found")
                .style(Style::default().fg(Color::DarkGray));
            msg.render(inner, buf);
            return;
        }

        // Header - TAG left-aligned, COUNT right-aligned
        buf.set_string(
            inner.x,
            inner.y,
            "TAG",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        );
        let count_header = "COUNT";
        buf.set_string(
            inner.x + inner.width - count_header.len() as u16,
            inner.y,
            count_header,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        );

        // Separator
        for x in inner.x..inner.x + inner.width {
            buf.set_string(x, inner.y + 1, "─", Style::default().fg(Color::DarkGray));
        }

        // Calculate scroll offset to keep selected visible
        let content_height = inner.height.saturating_sub(2) as usize;
        let scroll_offset = if self.state.selected >= content_height {
            self.state.selected - content_height + 1
        } else {
            0
        };

        // Tags list
        let content_y = inner.y + 2;
        for (i, (tag, count)) in self.state.tags.iter().enumerate().skip(scroll_offset) {
            let row = i - scroll_offset;
            if row >= content_height {
                break;
            }

            let y = content_y + row as u16;
            let is_cursor = i == self.state.selected;
            let is_checked = self.state.selected_tags.contains(tag);

            let style = if is_cursor {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };

            // Clear line for selection highlight
            if is_cursor {
                for x in inner.x..inner.x + inner.width {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.set_bg(Color::DarkGray);
                    }
                }
            }

            // Checkbox indicator
            let checkbox = if is_checked { "󰗠 " } else { "󰄰 " };
            buf.set_string(
                inner.x,
                y,
                checkbox,
                if is_cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::Green)
                } else {
                    Style::default().fg(Color::Green)
                },
            );

            // Tag name (truncate if needed, accounting for checkbox and count)
            let checkbox_width = 2u16;
            let count_width = 6u16;
            let max_tag_width = (inner.width as usize).saturating_sub((checkbox_width + count_width) as usize);
            let display_tag: String = if tag.len() > max_tag_width {
                format!("{}…", &tag[..max_tag_width.saturating_sub(1)])
            } else {
                tag.clone()
            };
            buf.set_string(inner.x + checkbox_width, y, &display_tag, style);

            // Count (right-aligned)
            let count_str = format!("{:>5}", count);
            buf.set_string(
                inner.x + inner.width - 5,
                y,
                &count_str,
                if is_cursor {
                    Style::default().bg(Color::DarkGray).fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::Cyan)
                },
            );
        }

        // Footer
        let footer = " j/k nav - Space select - Enter filter - q close ";
        let footer_y = popup.y + popup.height - 1;
        let footer_x = popup.x + (popup.width.saturating_sub(footer.len() as u16)) / 2;
        buf.set_string(footer_x, footer_y, footer, Style::default().fg(Color::DarkGray));
    }
}

/// Column widths for logs table
#[derive(Clone)]
struct LogsColumns {
    timestamp: u16,
    action: u16,
    name: u16,
    username: u16,
    details: u16,
}

impl LogsColumns {
    const GAP: u16 = 2;

    /// Calculate column widths based on actual content in logs
    fn from_logs(logs: &[AuditLog]) -> Self {
        // Find max content widths
        let max_name = logs.iter()
            .filter_map(|l| l.credential_name.as_ref())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(4) as u16;  // "NAME" header

        let max_username = logs.iter()
            .filter_map(|l| l.username.as_ref())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(8) as u16;  // "USERNAME" header

        let max_details = logs.iter()
            .filter_map(|l| l.details.as_ref())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(7) as u16;  // "DETAILS" header

        Self {
            timestamp: 20,  // "DD-Mon-YYYY at HH:MM" fixed
            action: 8,      // "UNLOCK" is longest action, header is "ACTION"
            name: max_name.max(4),      // At least "NAME"
            username: max_username.max(8),  // At least "USERNAME"
            details: max_details.max(7),    // At least "DETAILS"
        }
    }

    /// Total width needed for all columns
    fn total_width(&self) -> u16 {
        self.timestamp + self.action + self.name + self.username + self.details + (Self::GAP * 4)
    }

    /// Get column start X positions (relative to 0)
    fn positions(&self) -> (u16, u16, u16, u16, u16) {
        let ts_x = 0;
        let act_x = ts_x + self.timestamp + Self::GAP;
        let name_x = act_x + self.action + Self::GAP;
        let user_x = name_x + self.name + Self::GAP;
        let det_x = user_x + self.username + Self::GAP;
        (ts_x, act_x, name_x, user_x, det_x)
    }
}

/// Scrollable logs screen state
#[derive(Default)]
pub struct LogsState {
    pub scroll: ScrollState,
    pub logs: Vec<AuditLog>,
    columns: Option<LogsColumns>,
}

impl LogsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_logs(&mut self, logs: Vec<AuditLog>) {
        self.columns = Some(LogsColumns::from_logs(&logs));
        self.logs = logs;
        self.scroll.reset();
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll.scroll_up(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_down(amount, max);
    }

    pub fn scroll_left(&mut self, amount: usize) {
        self.scroll.scroll_left(amount);
    }

    pub fn scroll_right(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_right(amount, max);
    }

    pub fn home(&mut self) {
        self.scroll.home();
    }

    pub fn end(&mut self, max: usize) {
        self.scroll.end(max);
    }

    pub fn h_home(&mut self) {
        self.scroll.h_home();
    }

    pub fn h_end(&mut self, max: usize) {
        self.scroll.h_end(max);
    }

    /// Calculate max vertical scroll given visible height
    pub fn max_scroll(&self, visible_height: u16) -> usize {
        self.logs.len().saturating_sub(visible_height as usize)
    }

    /// Calculate max horizontal scroll given visible width
    pub fn max_h_scroll(&self, visible_width: u16) -> usize {
        let total = self.columns.as_ref()
            .map(|c| c.total_width())
            .unwrap_or(0);
        (total as usize).saturating_sub(visible_width as usize)
    }

    fn columns(&self) -> LogsColumns {
        self.columns.clone().unwrap_or_else(|| LogsColumns::from_logs(&self.logs))
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

    /// Calculate visible height for the logs popup given terminal area
    pub fn visible_height(area: Rect) -> u16 {
        let popup = centered_rect(85, 75, area);
        // inner area minus header (1) and separator (1)
        popup.height.saturating_sub(2).saturating_sub(2)
    }

    /// Calculate visible width for the logs popup given terminal area
    pub fn visible_width(area: Rect) -> u16 {
        let popup = centered_rect(85, 75, area);
        popup.width.saturating_sub(2) // minus borders
    }
}

impl Widget for LogsScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(85, 75, area);
        Clear.render(popup, buf);

        let block = Block::default()
            .title(" Audit Logs ")
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

        let columns = self.state.columns();
        let total_width = columns.total_width();
        let max_h_scroll = (total_width as usize).saturating_sub(inner.width as usize);
        let needs_h_scroll = max_h_scroll > 0;

        // Render footer
        let footer_text = if needs_h_scroll {
            " j/k scroll - h/l pan - 0/$ pan start/end - q close "
        } else {
            " j/k scroll - gg/G top/bottom - q close "
        };
        let footer_y = popup.y + popup.height - 1;
        let footer_x = popup.x + (popup.width.saturating_sub(footer_text.len() as u16)) / 2;
        buf.set_string(footer_x, footer_y, footer_text, Style::default().fg(Color::DarkGray));

        let h_offset = self.state.scroll.h_scroll;
        let (ts_x, act_x, name_x, user_x, det_x) = columns.positions();

        // Render header
        let header_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
        render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset,
            ts_x, "TIMESTAMP", header_style);
        render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset,
            act_x, "ACTION", header_style);
        render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset,
            name_x, "NAME", header_style);
        render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset,
            user_x, "USERNAME", header_style);
        render_text_at_virtual_x(buf, inner.x, inner.y, inner.width, h_offset,
            det_x, "DETAILS", header_style);

        // Render separator
        let sep_y = inner.y + 1;
        for x in inner.x..inner.x + inner.width {
            buf.set_string(x, sep_y, "─", Style::default().fg(Color::DarkGray));
        }

        // Render log entries (visible area starts after header + separator)
        let content_start_y = inner.y + 2;
        let visible_height = inner.height.saturating_sub(2) as usize;

        for (i, log) in self.state.logs.iter().enumerate().skip(self.state.scroll.v_scroll) {
            let row_idx = i - self.state.scroll.v_scroll;
            if row_idx >= visible_height {
                break;
            }

            let y = content_start_y + row_idx as u16;
            render_log_row(inner.x, y, inner.width, h_offset, &columns, log, buf);
        }

        // Render scroll indicator (arrows showing available scroll directions)
        if needs_h_scroll {
            let indicator = if h_offset == 0 {
                "  "
            } else if h_offset >= max_h_scroll {
                "  "
            } else {
                "  "
            };
            let ind_x = inner.x + inner.width.saturating_sub(indicator.len() as u16);
            buf.set_string(ind_x, inner.y, indicator, Style::default().fg(Color::Cyan));
        }
    }
}

/// Render text at a virtual X position, handling horizontal scroll
/// Text is NOT truncated - it's clipped by the view bounds only
fn render_text_at_virtual_x(
    buf: &mut Buffer,
    base_x: u16,
    y: u16,
    view_width: u16,
    h_offset: usize,
    virtual_x: u16,
    text: &str,
    style: Style,
) {
    let h_off = h_offset as u16;
    let text_len = text.chars().count() as u16;

    // If virtual_x + text length is before the scroll offset, text is off-screen left
    if virtual_x + text_len <= h_off {
        return;
    }

    // If virtual_x is past the visible area, text is off-screen right
    if virtual_x >= h_off + view_width {
        return;
    }

    let screen_x = if virtual_x >= h_off {
        base_x + virtual_x - h_off
    } else {
        base_x
    };

    // Calculate how much of the text to skip (if scrolled past start)
    let skip_chars = if virtual_x < h_off {
        (h_off - virtual_x) as usize
    } else {
        0
    };

    // Calculate available width on screen from screen_x to edge
    let available = (base_x + view_width).saturating_sub(screen_x) as usize;

    // Get visible portion of text (skip from left, take up to available width)
    let visible_text: String = text.chars()
        .skip(skip_chars)
        .take(available)
        .collect();

    buf.set_string(screen_x, y, &visible_text, style);
}

fn render_log_row(
    base_x: u16,
    y: u16,
    view_width: u16,
    h_offset: usize,
    columns: &LogsColumns,
    log: &AuditLog,
    buf: &mut Buffer,
) {
    let (ts_x, act_x, name_x, user_x, det_x) = columns.positions();

    // Format timestamp
    let timestamp = log.timestamp.format("%d-%b-%Y at %H:%M").to_string();

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

    let cred_name = log.credential_name.as_deref().unwrap_or("-");
    let username = log.username.as_deref().unwrap_or("-");
    let details = log.details.as_deref().unwrap_or("-");

    render_text_at_virtual_x(buf, base_x, y, view_width, h_offset,
        ts_x, &timestamp, Style::default().fg(Color::Magenta));
    render_text_at_virtual_x(buf, base_x, y, view_width, h_offset,
        act_x, action_str, Style::default().fg(action_color));
    render_text_at_virtual_x(buf, base_x, y, view_width, h_offset,
        name_x, cred_name, Style::default().fg(Color::White));
    render_text_at_virtual_x(buf, base_x, y, view_width, h_offset,
        user_x, username, Style::default().fg(Color::White));
    render_text_at_virtual_x(buf, base_x, y, view_width, h_offset,
        det_x, details, Style::default().fg(Color::DarkGray));
}

/// Scrollable help screen state
#[derive(Default)]
pub struct HelpState {
    pub scroll: ScrollState,
}

impl HelpState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll.scroll_up(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_down(amount, max);
    }

    pub fn scroll_left(&mut self, amount: usize) {
        self.scroll.scroll_left(amount);
    }

    pub fn scroll_right(&mut self, amount: usize, max: usize) {
        self.scroll.scroll_right(amount, max);
    }

    pub fn home(&mut self) {
        self.scroll.home();
    }

    pub fn end(&mut self, max: usize) {
        self.scroll.end(max);
    }

    pub fn h_home(&mut self) {
        self.scroll.h_home();
    }

    pub fn h_end(&mut self, max: usize) {
        self.scroll.h_end(max);
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

    /// Calculate total content height for single-column mode
    fn single_column_height() -> usize {
        help_sections()
            .iter()
            .map(|(_, bindings)| 1 + bindings.len() + 1)
            .sum::<usize>()
            .saturating_sub(1)
    }

    /// Calculate total content height for two-column mode
    fn two_column_height() -> usize {
        let sections = help_sections();
        let (left, right) = split_sections_for_columns(&sections);
        let left_height: usize = left.iter().map(|(_, b)| 1 + b.len() + 1).sum::<usize>().saturating_sub(1);
        let right_height: usize = right.iter().map(|(_, b)| 1 + b.len() + 1).sum::<usize>().saturating_sub(1);
        left_height.max(right_height)
    }

    /// Calculate content width for single-column mode
    fn single_column_width() -> usize {
        let sections = help_sections();
        let mut max_width = 0usize;
        for (header, bindings) in &sections {
            max_width = max_width.max(header.len());
            for (_key, desc) in bindings {
                // 4 indent + key + gap to 16 + desc
                let line_width = 16 + desc.len();
                max_width = max_width.max(line_width);
            }
        }
        max_width
    }

    /// Calculate content height based on whether two columns will be used
    pub fn content_height(area: Rect) -> usize {
        let popup = centered_rect(65, 65, area);
        let inner_width = popup.width.saturating_sub(2);
        if inner_width >= TWO_COLUMN_MIN_WIDTH {
            Self::two_column_height()
        } else {
            Self::single_column_height()
        }
    }

    /// Calculate max scroll value given terminal area
    pub fn max_scroll(area: Rect) -> usize {
        let visible = Self::visible_height(area) as usize;
        let content = Self::content_height(area);
        content.saturating_sub(visible)
    }

    /// Calculate max horizontal scroll
    pub fn max_h_scroll(area: Rect) -> usize {
        let popup = centered_rect(65, 65, area);
        let inner_width = popup.width.saturating_sub(2) as usize;
        let content_width = Self::single_column_width();
        content_width.saturating_sub(inner_width)
    }

    /// Calculate visible height for the help popup given terminal area
    pub fn visible_height(area: Rect) -> u16 {
        let popup = centered_rect(65, 65, area);
        popup.height.saturating_sub(2)
    }
}

const TWO_COLUMN_MIN_WIDTH: u16 = 85;

impl Widget for HelpScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(65, 65, area);
        Clear.render(popup, buf);

        let block = Block::default()
            .title(" Help Page ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(popup);
        block.render(popup, buf);

        let use_two_columns = inner.width >= TWO_COLUMN_MIN_WIDTH;
        let max_h_scroll = if use_two_columns { 0 } else { HelpScreen::max_h_scroll(area) };
        let needs_h_scroll = max_h_scroll > 0;

        // Render footer
        let footer_text = if needs_h_scroll {
            " j/k scroll - h/l pan - gg/G top/bottom - q close "
        } else {
            " j/k scroll - gg/G top/bottom - q close "
        };
        let footer_y = popup.y + popup.height - 1;
        let footer_x = popup.x + (popup.width.saturating_sub(footer_text.len() as u16)) / 2;
        buf.set_string(footer_x, footer_y, footer_text, Style::default().fg(Color::DarkGray));

        if use_two_columns {
            render_two_columns(inner, buf, self.state.scroll.v_scroll);
        } else {
            render_single_column(inner, buf, self.state.scroll.v_scroll, self.state.scroll.h_scroll);
        }

        // Render h-scroll indicator for single column
        if needs_h_scroll {
            let h_offset = self.state.scroll.h_scroll;
            let indicator = if h_offset == 0 {
                " → "
            } else if h_offset >= max_h_scroll {
                " ← "
            } else {
                " ←→ "
            };
            let ind_x = inner.x + inner.width.saturating_sub(indicator.len() as u16);
            buf.set_string(ind_x, inner.y, indicator, Style::default().fg(Color::Cyan));
        }
    }
}

fn render_single_column(area: Rect, buf: &mut Buffer, v_scroll: usize, h_scroll: usize) {
    let sections = help_sections();
    let lines = build_help_lines(&sections);

    for (i, line) in lines.iter().enumerate().skip(v_scroll) {
        let y = area.y + (i - v_scroll) as u16;
        if y >= area.y + area.height {
            break;
        }
        render_help_line_scrollable(area.x, y, area.width, h_scroll, line, buf);
    }
}

fn render_two_columns(area: Rect, buf: &mut Buffer, v_scroll: usize) {
    let sections = help_sections();
    let (left_sections, right_sections) = split_sections_for_columns(&sections);

    let left_lines = build_help_lines(&left_sections);
    let right_lines = build_help_lines(&right_sections);

    let gap = 4u16;
    let col_width = (area.width.saturating_sub(gap)) / 2;
    let right_x = area.x + col_width + gap;

    let max_lines = left_lines.len().max(right_lines.len());

    for i in v_scroll..max_lines {
        let y = area.y + (i - v_scroll) as u16;
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
            buf.set_string(x + 4, y, *key, Style::default().fg(Color::Cyan));
            let desc_x = x + 16;
            let desc_width = width.saturating_sub(16) as usize;
            let truncated: String = desc.chars().take(desc_width).collect();
            buf.set_string(desc_x, y, &truncated, Style::default().fg(Color::Gray));
        }
        HelpLine::Empty => {}
    }
}

fn render_help_line_scrollable(base_x: u16, y: u16, view_width: u16, h_scroll: usize, line: &HelpLine, buf: &mut Buffer) {
    match line {
        HelpLine::Header(title) => {
            render_text_at_virtual_x(buf, base_x, y, view_width, h_scroll,
                0, title,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        }
        HelpLine::Binding(key, desc) => {
            // Key at indent 4
            render_text_at_virtual_x(buf, base_x, y, view_width, h_scroll,
                4, key, Style::default().fg(Color::Cyan));
            // Description at position 16
            render_text_at_virtual_x(buf, base_x, y, view_width, h_scroll,
                16, desc, Style::default().fg(Color::Gray));
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
                ("T", "Copy TOTP code"),
            ],
        ),
        (
            "View",
            vec![
                ("Ctrl+s", "Toggle password"),
                ("/", "Search"),
                ("t", "Show tags"),
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
                (":tag", "View tags"),
                (":new", "New credential"),
                (":gen", "Generate password"),
            ],
        ),
        (
            "Other",
            vec![
                ("?", "Show this help"),
                ("Ctrl+l", "Clear message"),
                ("Ctrl+p", "Change master key"),
                ("L", "Lock vault"),
                ("t", "View tags"),
                ("i", "View logs"),
                ("q", "Quit"),
            ],
        ),
    ]
}
