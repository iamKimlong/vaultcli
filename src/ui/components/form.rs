//! Credential Form Component
//!
//! Multi-field form for creating and editing credentials.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Clear, Paragraph, Widget, Wrap},
};

use crate::db::models::CredentialType;
use crate::ui::renderer::View;

/// Form field definition
#[derive(Debug, Clone)]
pub struct FormField {
    pub label: &'static str,
    pub value: String,
    pub required: bool,
    pub masked: bool,
    pub field_type: FieldType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Password,
    Select,
    MultiLine,
}

impl FormField {
    pub fn text(label: &'static str, required: bool) -> Self {
        Self {
            label,
            value: String::new(),
            required,
            masked: false,
            field_type: FieldType::Text,
        }
    }

    pub fn password(label: &'static str, required: bool) -> Self {
        Self {
            label,
            value: String::new(),
            required,
            masked: true,
            field_type: FieldType::Password,
        }
    }

    pub fn select(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: true,
            masked: false,
            field_type: FieldType::Select,
        }
    }

    pub fn multiline(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: false,
            masked: false,
            field_type: FieldType::MultiLine,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }
}

/// Credential form state
#[derive(Debug, Clone)]
pub struct CredentialForm {
    pub fields: Vec<FormField>,
    pub active_field: usize,
    pub cursor: usize,
    pub credential_type: CredentialType,
    pub editing_id: Option<String>,
    pub show_password: bool,
    pub scroll_offset: usize,
    pub previous_view: View,
}

impl Default for CredentialForm {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialForm {
    pub fn new() -> Self {
        Self {
            fields: vec![
                FormField::text("Name", true),
                FormField::select("Type"),
                FormField::text("Username", false),
                FormField::password("Password/Secret", true),
                FormField::text("URL", false),
                FormField::text("Tags", false),
                FormField::multiline("Notes"),
            ],
            active_field: 0,
            cursor: 0,
            credential_type: CredentialType::Password,
            editing_id: None,
            show_password: false,
            scroll_offset: 0,
            previous_view: View::List,
        }
    }

    pub fn for_edit(
        id: String,
        name: String,
        cred_type: CredentialType,
        username: Option<String>,
        secret: String,
        url: Option<String>,
        tags: Vec<String>,
        notes: Option<String>,
        previous_view: View,
    ) -> Self {
        let mut form = Self::new();
        form.editing_id = Some(id);
        form.credential_type = cred_type;
        form.previous_view = previous_view;

        form.fields[0].value = name;
        form.fields[1].value = cred_type.display_name().to_string();
        form.fields[2].value = username.unwrap_or_default();
        form.fields[3].value = secret;
        form.fields[4].value = url.unwrap_or_default();
        form.fields[5].value = tags.join(", ");
        form.fields[6].value = notes.unwrap_or_default();

        form
    }

    pub fn is_editing(&self) -> bool {
        self.editing_id.is_some()
    }

    pub fn active_field(&self) -> &FormField {
        &self.fields[self.active_field]
    }

    pub fn active_field_mut(&mut self) -> &mut FormField {
        &mut self.fields[self.active_field]
    }

    fn ensure_visible(&mut self, visible_fields: usize) {
        if self.active_field < self.scroll_offset {
            self.scroll_offset = self.active_field;
        } else if self.active_field >= self.scroll_offset + visible_fields {
            self.scroll_offset = self.active_field - visible_fields + 1;
        }
    }

    pub fn next_field(&mut self) {
        self.active_field = (self.active_field + 1) % self.fields.len();
        self.cursor = self.fields[self.active_field].value.len();
        self.ensure_visible(5);
    }

    pub fn prev_field(&mut self) {
        if self.active_field == 0 {
            self.active_field = self.fields.len() - 1;
        } else {
            self.active_field -= 1;
        }
        self.cursor = self.fields[self.active_field].value.len();
        self.ensure_visible(5);
    }

    pub fn insert_char(&mut self, c: char) {
        let field = &mut self.fields[self.active_field];
        if field.field_type != FieldType::Select {
            field.value.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    pub fn delete_char(&mut self) {
        let field = &mut self.fields[self.active_field];
        if self.cursor > 0 && field.field_type != FieldType::Select {
            self.cursor -= 1;
            field.value.remove(self.cursor);
        }
    }

    pub fn cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn cursor_right(&mut self) {
        if self.cursor < self.fields[self.active_field].value.len() {
            self.cursor += 1;
        }
    }

    pub fn cycle_type(&mut self, forward: bool) {
        if self.fields[self.active_field].field_type == FieldType::Select {
            self.credential_type = if forward {
                match self.credential_type {
                    CredentialType::Password => CredentialType::ApiKey,
                    CredentialType::ApiKey => CredentialType::SshKey,
                    CredentialType::SshKey => CredentialType::Certificate,
                    CredentialType::Certificate => CredentialType::Totp,
                    CredentialType::Totp => CredentialType::Note,
                    CredentialType::Note => CredentialType::Database,
                    CredentialType::Database => CredentialType::Custom,
                    CredentialType::Custom => CredentialType::Password,
                }
            } else {
                match self.credential_type {
                    CredentialType::Password => CredentialType::Custom,
                    CredentialType::ApiKey => CredentialType::Password,
                    CredentialType::SshKey => CredentialType::ApiKey,
                    CredentialType::Certificate => CredentialType::SshKey,
                    CredentialType::Totp => CredentialType::Certificate,
                    CredentialType::Note => CredentialType::Totp,
                    CredentialType::Database => CredentialType::Note,
                    CredentialType::Custom => CredentialType::Database,
                }
            };
            self.fields[1].value = self.credential_type.display_name().to_string();
        }
    }

    pub fn toggle_password_visibility(&mut self) {
        self.show_password = !self.show_password;
    }

    pub fn validate(&self) -> Result<(), String> {
        for field in &self.fields {
            if field.required && field.value.trim().is_empty() {
                return Err(format!("{} is required", field.label));
            }
        }
        Ok(())
    }

    pub fn get_name(&self) -> &str {
        &self.fields[0].value
    }

    pub fn get_username(&self) -> Option<String> {
        let val = self.fields[2].value.trim();
        if val.is_empty() { None } else { Some(val.to_string()) }
    }

    pub fn get_secret(&self) -> &str {
        &self.fields[3].value
    }

    pub fn get_url(&self) -> Option<String> {
        let val = self.fields[4].value.trim();
        if val.is_empty() { None } else { Some(val.to_string()) }
    }

    pub fn get_tags(&self) -> Vec<String> {
        self.fields[5]
            .value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn get_notes(&self) -> Option<String> {
        let val = self.fields[6].value.trim();
        if val.is_empty() { None } else { Some(val.to_string()) }
    }
}

/// Credential form widget
pub struct CredentialFormWidget<'a> {
    form: &'a CredentialForm,
    title: &'a str,
}

impl<'a> CredentialFormWidget<'a> {
    pub fn new(form: &'a CredentialForm) -> Self {
        let title = if form.is_editing() {
            " Edit Credential "
        } else {
            " New Credential "
        };
        Self { form, title }
    }
}

impl<'a> Widget for CredentialFormWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Center the form
        let form_width = 70u16.min(area.width.saturating_sub(4));
        let form_height = 20u16.min(area.height.saturating_sub(2));
        let form_x = area.x + (area.width.saturating_sub(form_width)) / 2;
        let form_y = area.y + (area.height.saturating_sub(form_height)) / 2;
        let form_area = Rect::new(form_x, form_y, form_width, form_height);

        // Clear background
        Clear.render(form_area, buf);

        // Draw border
        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(form_area);
        block.render(form_area, buf);

        // Calculate field layout
        let has_up_indicator = self.form.scroll_offset > 0;
        let mut y = if has_up_indicator { inner.y + 1 } else { inner.y };
        let label_width = 18u16;
        let visible_height = inner.height.saturating_sub(2);
        let max_visible_fields = (visible_height / 2) as usize;

        // Show scroll indicator at top if scrolled
        if self.form.scroll_offset > 0 {
            let indicator = "";
            let x = inner.x + (inner.width.saturating_sub(indicator.len() as u16)) / 2;
            buf.set_string(x, inner.y, indicator, Style::default().fg(Color::Magenta));
        }

        for (i, field) in self.form.fields.iter().enumerate().skip(self.form.scroll_offset) {
            if i >= self.form.scroll_offset + max_visible_fields {
                break;
            }

            let is_active = i == self.form.active_field;

            // Label with required indicator
            let label = if field.required {
                format!("{}*:", field.label)
            } else {
                format!("{}:", field.label)
            };

            let label_style = if is_active {
                Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };

            buf.set_string(inner.x, y, &label, label_style);

            // Value field
            let value_x = inner.x + label_width;
            let value_width = inner.width.saturating_sub(label_width + 1);

            // Field background
            let field_style = if is_active {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            for x in value_x..value_x + value_width {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_style(field_style);
                }
            }

            // Field value
            let display_value = if field.field_type == FieldType::Select {
                // Show type with icon
                let icon = self.form.credential_type.icon();
                format!("{} {} [Space/Ctrl+Space]", icon, field.value)
            } else if field.masked && !self.form.show_password {
                "*".repeat(field.value.len().min(value_width as usize))
            } else {
                field.value.clone()
            };

            let value_style = if field.field_type == FieldType::Select {
                Style::default().fg(Color::Yellow)
            } else if field.masked {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::White)
            };

            buf.set_string(value_x, y, &display_value, value_style.bg(if is_active { Color::DarkGray } else { Color::Black }));

            // Cursor
            if is_active && field.field_type != FieldType::Select {
                let cursor_x = value_x + self.form.cursor as u16;
                if cursor_x < value_x + value_width {
                    if let Some(cell) = buf.cell_mut((cursor_x, y)) {
                        cell.set_style(Style::default().bg(Color::White).fg(Color::Black));
                    }
                }
            }

            y += 2; // Space between fields
        }

        // Show scroll indicator at bottom if more fields below
        if self.form.scroll_offset + max_visible_fields < self.form.fields.len() {
            let indicator = "";
            let x = inner.x + (inner.width.saturating_sub(indicator.len() as u16)) / 2;
            buf.set_string(x, inner.y + inner.height - 2, indicator, Style::default().fg(Color::Magenta));
        }

        // Help text at bottom
        let help_y = inner.y + inner.height - 1;
        let help_text = Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Magenta)),
            Span::raw(" next  "),
            Span::styled("Shift+Tab", Style::default().fg(Color::Magenta)),
            Span::raw(" prev  "),
            Span::styled("Enter", Style::default().fg(Color::Magenta)),
            Span::raw(" save  "),
            Span::styled("Esc", Style::default().fg(Color::Magenta)),
            Span::raw(" cancel  "),
            Span::styled("Ctrl+s", Style::default().fg(Color::Magenta)),
            Span::raw(" show pwd"),
        ]);
        buf.set_line(inner.x, help_y, &help_text, inner.width);
    }
}
