//! Detail View Component
//!
//! Displays credential details in a panel.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Paragraph, Widget, Wrap},
};

use crate::db::models::CredentialType;

#[derive(Debug, Clone)]
pub struct CredentialDetail {
    pub name: String,
    pub credential_type: CredentialType,
    pub username: Option<String>,
    pub secret: Option<String>,
    pub secret_visible: bool,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub totp_code: Option<String>,
    pub totp_remaining: Option<u64>,
}

pub struct DetailView<'a> {
    detail: &'a CredentialDetail,
}

impl<'a> DetailView<'a> {
    pub fn new(detail: &'a CredentialDetail) -> Self {
        Self { detail }
    }
}

fn render_field(buf: &mut Buffer, x: u16, y: &mut u16, _width: u16, label: &str, value: &[Span]) {
    let label_style = Style::default().fg(Color::DarkGray);
    buf.set_string(x, *y, format!("{}:", label), label_style);

    let value_x = x + 12;
    let line = Line::from(value.to_vec());
    buf.set_line(value_x, *y, &line, 60);

    *y += 1;
}

fn type_color(cred_type: CredentialType) -> Color {
    match cred_type {
        CredentialType::Password => Color::Green,
        CredentialType::ApiKey => Color::Yellow,
        CredentialType::SshKey => Color::Cyan,
        CredentialType::Certificate => Color::Magenta,
        CredentialType::Totp => Color::Blue,
        CredentialType::Note => Color::Gray,
        CredentialType::Database => Color::Red,
        CredentialType::Custom => Color::White,
    }
}

fn strength_color(strength: u32) -> Color {
    match strength {
        0..=20 => Color::Red,
        21..=40 => Color::LightRed,
        41..=60 => Color::Yellow,
        61..=80 => Color::LightGreen,
        _ => Color::Green,
    }
}

fn render_type_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, detail: &CredentialDetail) {
    let color = type_color(detail.credential_type);
    let value_style = Style::default().fg(Color::White);
    render_field(buf, x, y, width, "Type", &[
        Span::styled(detail.credential_type.icon(), Style::default().fg(color)),
        Span::raw(" "),
        Span::styled(detail.credential_type.display_name(), value_style),
    ]);
}

fn render_username_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, username: &str) {
    let value_style = Style::default().fg(Color::White);
    render_field(buf, x, y, width, "Username", &[Span::styled(username, value_style)]);
}

fn render_secret_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, secret: &str, visible: bool) {
    let secret_style = Style::default().fg(Color::Yellow);
    let display_secret = if visible {
        secret.to_string()
    } else {
        "•".repeat(secret.len().min(20))
    };
    render_field(buf, x, y, width, "Secret", &[Span::styled(display_secret, secret_style)]);
}

fn render_strength_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, secret: &str) {
    let strength = crate::crypto::password_strength(secret);
    let label = crate::crypto::strength_label(strength);
    let color = strength_color(strength);
    render_field(buf, x, y, width, "Strength", &[
        Span::styled(format!("{} ({}%)", label, strength), Style::default().fg(color)),
    ]);
}

fn render_totp_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, code: &str, remaining: u64) {
    render_field(buf, x, y, width, "TOTP", &[
        Span::styled(code, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" ({}s)", remaining), Style::default().fg(Color::DarkGray)),
    ]);
}

fn render_url_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, url: &str) {
    render_field(buf, x, y, width, "URL", &[
        Span::styled(url, Style::default().fg(Color::Blue)),
    ]);
}

fn render_tags_field(buf: &mut Buffer, x: u16, y: &mut u16, width: u16, tags: &[String]) {
    let tag_spans: Vec<Span> = tags
        .iter()
        .flat_map(|tag| vec![
            Span::styled(format!("#{}", tag), Style::default().fg(Color::Magenta)),
            Span::raw(" "),
        ])
        .collect();
    render_field(buf, x, y, width, "Tags", &tag_spans);
}

fn render_notes_section(buf: &mut Buffer, inner: &Rect, y: &mut u16, notes: &str) {
    let label_style = Style::default().fg(Color::DarkGray);
    buf.set_string(inner.x, *y, "Notes:", label_style);
    *y += 1;

    let note_area = Rect::new(inner.x, *y, inner.width, inner.height.saturating_sub(*y - inner.y));
    let note_widget = Paragraph::new(notes)
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true });
    note_widget.render(note_area, buf);
}

fn render_timestamps(buf: &mut Buffer, inner: &Rect, y: u16, created: &str, updated: &str) {
    let footer_y = inner.y + inner.height.saturating_sub(2);
    if footer_y <= y {
        return;
    }
    let style = Style::default().fg(Color::DarkGray);
    buf.set_string(inner.x, footer_y, format!("Created: {}", created), style);
    buf.set_string(inner.x, footer_y + 1, format!("Updated: {}", updated), style);
}

fn render_detail_block(area: Rect, buf: &mut Buffer, name: &str) -> Rect {
    let block = Block::default()
        .title(format!(" {} ", name))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = block.inner(area);
    block.render(area, buf);
    inner
}

impl<'a> Widget for DetailView<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let inner = render_detail_block(area, buf, &self.detail.name);
        let mut y = inner.y;

        render_type_field(buf, inner.x, &mut y, inner.width, self.detail);

        if let Some(ref username) = self.detail.username {
            render_username_field(buf, inner.x, &mut y, inner.width, username);
        }

        if let Some(ref secret) = self.detail.secret {
            render_secret_field(buf, inner.x, &mut y, inner.width, secret, self.detail.secret_visible);
            if self.detail.credential_type == CredentialType::Password { render_strength_field(buf, inner.x, &mut y, inner.width, secret); }
        }

        if let (Some(code), Some(remaining)) = (&self.detail.totp_code, self.detail.totp_remaining) {
            render_totp_field(buf, inner.x, &mut y, inner.width, code, remaining);
        }

        if let Some(ref url) = self.detail.url {
            render_url_field(buf, inner.x, &mut y, inner.width, url);
        }

        if !self.detail.tags.is_empty() {
            render_tags_field(buf, inner.x, &mut y, inner.width, &self.detail.tags);
        }

        y += 1;

        if let Some(ref notes) = self.detail.notes {
            render_notes_section(buf, &inner, &mut y, notes);
        }

        render_timestamps(buf, &inner, y, &self.detail.created_at, &self.detail.updated_at);
    }
}

pub struct PasswordStrength {
    strength: u32,
}

impl PasswordStrength {
    pub fn new(password: &str) -> Self {
        Self {
            strength: crate::crypto::password_strength(password),
        }
    }
}

fn render_strength_bar(buf: &mut Buffer, area: Rect, filled: u16, color: Color) {
    for x in area.x..area.x + area.width {
        let style = if x < area.x + filled {
            Style::default().bg(color)
        } else {
            Style::default().bg(Color::DarkGray)
        };
        if let Some(cell) = buf.cell_mut((x, area.y)) {
            cell.set_style(style);
        }
    }
}

impl Widget for PasswordStrength {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let filled = (self.strength as f32 / 100.0 * area.width as f32) as u16;
        let color = strength_color(self.strength);

        render_strength_bar(buf, area, filled, color);

        let label = crate::crypto::strength_label(self.strength);
        let label_x = area.x + (area.width.saturating_sub(label.len() as u16)) / 2;
        buf.set_string(label_x, area.y, label, Style::default().fg(Color::White));
    }
}

pub struct TotpDisplay<'a> {
    code: &'a str,
    remaining: u64,
    period: u64,
}

impl<'a> TotpDisplay<'a> {
    pub fn new(code: &'a str, remaining: u64, period: u64) -> Self {
        Self { code, remaining, period }
    }
}

fn render_countdown_bar(buf: &mut Buffer, area: Rect, remaining: u64, period: u64) {
    let bar_y = area.y + 1;
    let filled = (remaining as f32 / period as f32 * area.width as f32) as u16;
    let color = if remaining <= 5 { Color::Red } else { Color::Green };

    for x in area.x..area.x + area.width {
        let style = if x < area.x + filled {
            Style::default().bg(color)
        } else {
            Style::default().bg(Color::DarkGray)
        };
        if let Some(cell) = buf.cell_mut((x, bar_y)) {
            cell.set_style(style);
        }
    }
}

impl<'a> Widget for TotpDisplay<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_string(
            area.x,
            area.y,
            self.code,
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        );

        if area.height > 1 {
            render_countdown_bar(buf, area, self.remaining, self.period);
        }

        let time_str = format!("{}s", self.remaining);
        let time_x = area.x + area.width.saturating_sub(time_str.len() as u16);
        buf.set_string(time_x, area.y, &time_str, Style::default().fg(Color::DarkGray));
    }
}
