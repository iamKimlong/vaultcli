//! Detail View Component
//!
//! Displays credential details in a panel.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget, Wrap},
};

use crate::db::models::CredentialType;

/// Credential detail data
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
    pub project_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub totp_code: Option<String>,
    pub totp_remaining: Option<u64>,
}

/// Detail view widget
pub struct DetailView<'a> {
    detail: &'a CredentialDetail,
}

impl<'a> DetailView<'a> {
    pub fn new(detail: &'a CredentialDetail) -> Self {
        Self { detail }
    }
}

impl<'a> Widget for DetailView<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(format!(" {} ", self.detail.name))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = block.inner(area);
        block.render(area, buf);

        let mut y = inner.y;
        let label_style = Style::default().fg(Color::DarkGray);
        let value_style = Style::default().fg(Color::White);
        let secret_style = Style::default().fg(Color::Yellow);

        // Type
        let type_color = type_color(self.detail.credential_type);
        render_field(buf, inner.x, &mut y, inner.width, "Type", &[
            Span::styled(self.detail.credential_type.icon(), Style::default().fg(type_color)),
            Span::raw(" "),
            Span::styled(self.detail.credential_type.display_name(), value_style),
        ]);

        // Project
        render_field(buf, inner.x, &mut y, inner.width, "Project", &[
            Span::styled(&self.detail.project_name, Style::default().fg(Color::Cyan)),
        ]);

        // Username
        if let Some(ref username) = self.detail.username {
            render_field(buf, inner.x, &mut y, inner.width, "Username", &[
                Span::styled(username, value_style),
            ]);
        }

        // Secret/Password
        if let Some(ref secret) = self.detail.secret {
            let display_secret = if self.detail.secret_visible {
                secret.clone()
            } else {
                "•".repeat(secret.len().min(20))
            };
            render_field(buf, inner.x, &mut y, inner.width, "Secret", &[
                Span::styled(&display_secret, secret_style),
            ]);

            // Password strength
            if self.detail.credential_type == CredentialType::Password {
                let strength = crate::crypto::password_strength(secret);
                let label = crate::crypto::strength_label(strength);
                let color = strength_color(strength);
                render_field(buf, inner.x, &mut y, inner.width, "Strength", &[
                    Span::styled(format!("{} ({}%)", label, strength), Style::default().fg(color)),
                ]);
            }
        }

        // TOTP
        if let (Some(ref code), Some(remaining)) = (&self.detail.totp_code, self.detail.totp_remaining) {
            render_field(buf, inner.x, &mut y, inner.width, "TOTP", &[
                Span::styled(code, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" ({}s)", remaining), Style::default().fg(Color::DarkGray)),
            ]);
        }

        // URL
        if let Some(ref url) = self.detail.url {
            render_field(buf, inner.x, &mut y, inner.width, "URL", &[
                Span::styled(url, Style::default().fg(Color::Blue)),
            ]);
        }

        // Tags
        if !self.detail.tags.is_empty() {
            let tag_spans: Vec<Span> = self.detail.tags.iter()
                .flat_map(|tag| vec![
                    Span::styled(format!("#{}", tag), Style::default().fg(Color::Magenta)),
                    Span::raw(" "),
                ])
                .collect();
            render_field(buf, inner.x, &mut y, inner.width, "Tags", &tag_spans);
        }

        // Spacer
        y += 1;

        // Notes
        if let Some(ref notes) = self.detail.notes {
            buf.set_string(inner.x, y, "Notes:", label_style);
            y += 1;
            let note_area = Rect::new(inner.x, y, inner.width, inner.height.saturating_sub(y - inner.y));
            let note_widget = Paragraph::new(notes.as_str())
                .style(Style::default().fg(Color::Gray))
                .wrap(Wrap { trim: true });
            note_widget.render(note_area, buf);
        }

        // Timestamps at bottom
        let footer_y = inner.y + inner.height.saturating_sub(2);
        if footer_y > y {
            buf.set_string(
                inner.x,
                footer_y,
                format!("Created: {}", self.detail.created_at),
                Style::default().fg(Color::DarkGray),
            );
            buf.set_string(
                inner.x,
                footer_y + 1,
                format!("Updated: {}", self.detail.updated_at),
                Style::default().fg(Color::DarkGray),
            );
        }
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

/// Password strength indicator widget
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

impl Widget for PasswordStrength {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let filled = (self.strength as f32 / 100.0 * area.width as f32) as u16;
        let color = strength_color(self.strength);

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

        let label = crate::crypto::strength_label(self.strength);
        let label_x = area.x + (area.width.saturating_sub(label.len() as u16)) / 2;
        buf.set_string(label_x, area.y, label, Style::default().fg(Color::White));
    }
}

/// TOTP display widget
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

impl<'a> Widget for TotpDisplay<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Code
        buf.set_string(
            area.x,
            area.y,
            self.code,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        );

        // Countdown bar
        if area.height > 1 {
            let bar_y = area.y + 1;
            let filled = (self.remaining as f32 / self.period as f32 * area.width as f32) as u16;
            let color = if self.remaining <= 5 { Color::Red } else { Color::Green };

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

        // Remaining time
        let time_str = format!("{}s", self.remaining);
        let time_x = area.x + area.width.saturating_sub(time_str.len() as u16);
        buf.set_string(time_x, area.y, &time_str, Style::default().fg(Color::DarkGray));
    }
}
