//! Credential Form Component
//!
//! Multi-field form for creating and editing credentials.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, Clear, Widget},
};

use crate::db::models::CredentialType;
use crate::ui::renderer::View;

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

fn default_fields() -> Vec<FormField> {
    vec![
        FormField::text("Name", true),
        FormField::select("Type").with_value(CredentialType::Password.display_name()),
        FormField::text("Username", false),
        FormField::password("Password/Secret", true),
        FormField::text("URL", false),
        FormField::text("Tags (multiple)", false),
        FormField::multiline("Notes"),
    ]
}

fn cycle_type_forward(cred_type: CredentialType) -> CredentialType {
    match cred_type {
        CredentialType::Password => CredentialType::ApiKey,
        CredentialType::ApiKey => CredentialType::SshKey,
        CredentialType::SshKey => CredentialType::Certificate,
        CredentialType::Certificate => CredentialType::Totp,
        CredentialType::Totp => CredentialType::Note,
        CredentialType::Note => CredentialType::Database,
        CredentialType::Database => CredentialType::Custom,
        CredentialType::Custom => CredentialType::Password,
    }
}

fn cycle_type_backward(cred_type: CredentialType) -> CredentialType {
    match cred_type {
        CredentialType::Password => CredentialType::Custom,
        CredentialType::ApiKey => CredentialType::Password,
        CredentialType::SshKey => CredentialType::ApiKey,
        CredentialType::Certificate => CredentialType::SshKey,
        CredentialType::Totp => CredentialType::Certificate,
        CredentialType::Note => CredentialType::Totp,
        CredentialType::Database => CredentialType::Note,
        CredentialType::Custom => CredentialType::Database,
    }
}

fn trim_to_option(val: &str) -> Option<String> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

impl CredentialForm {
    pub fn new() -> Self {
        Self {
            fields: default_fields(),
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
        form.fields[5].value = tags.join(" ");
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
            return;
        }
        if self.active_field >= self.scroll_offset + visible_fields {
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
        if field.field_type == FieldType::Select {
            return;
        }
        field.value.insert(self.cursor, c);
        self.cursor += 1;
    }

    pub fn delete_char(&mut self) {
        let field = &mut self.fields[self.active_field];
        if self.cursor == 0 || field.field_type == FieldType::Select {
            return;
        }
        self.cursor -= 1;
        field.value.remove(self.cursor);
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
        if self.fields[self.active_field].field_type != FieldType::Select {
            return;
        }
        self.credential_type = if forward {
            cycle_type_forward(self.credential_type)
        } else {
            cycle_type_backward(self.credential_type)
        };
        self.fields[1].value = self.credential_type.display_name().to_string();
    }

    pub fn toggle_password_visibility(&mut self) {
        self.show_password = !self.show_password;
    }

    pub fn validate(&self) -> Result<(), String> {
        for field in &self.fields {
            let is_empty_required = field.required && field.value.trim().is_empty();
            if is_empty_required { return Err(format!("{} is required", field.label)); }
        }
        Ok(())
    }

    pub fn get_name(&self) -> &str {
        &self.fields[0].value
    }

    pub fn get_username(&self) -> Option<String> {
        trim_to_option(&self.fields[2].value)
    }

    pub fn get_secret(&self) -> &str {
        &self.fields[3].value
    }

    pub fn get_url(&self) -> Option<String> {
        trim_to_option(&self.fields[4].value)
    }

    pub fn get_tags(&self) -> Vec<String> {
        self.fields[5]
            .value
            .split(' ')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn get_notes(&self) -> Option<String> {
        trim_to_option(&self.fields[6].value)
    }
}

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

fn calculate_form_area(area: Rect) -> Rect {
    let form_width = 70u16.min(area.width.saturating_sub(4));
    let form_height = 20u16.min(area.height.saturating_sub(2));
    let form_x = area.x + (area.width.saturating_sub(form_width)) / 2;
    let form_y = area.y + (area.height.saturating_sub(form_height)) / 2;
    Rect::new(form_x, form_y, form_width, form_height)
}

fn render_form_block(buf: &mut Buffer, form_area: Rect, title: &str) -> Rect {
    Clear.render(form_area, buf);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta))
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(form_area);
    block.render(form_area, buf);
    inner
}

fn render_scroll_indicator(buf: &mut Buffer, inner: &Rect, at_top: bool) {
    let (y, icon) = if at_top {
        (inner.y, "")
    } else {
        (inner.y + inner.height - 2, "")
    };
    buf.set_string(inner.x + inner.width / 2, y, icon, Style::default().fg(Color::Magenta));
}

fn format_label(field: &FormField) -> String {
    if field.required {
        format!("{}*:", field.label)
    } else {
        format!("{}:", field.label)
    }
}

fn label_style(is_active: bool) -> Style {
    if is_active {
        Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn field_background_style(is_active: bool) -> Style {
    if is_active {
        Style::default().bg(Color::DarkGray)
    } else {
        Style::default()
    }
}

fn fill_field_background(buf: &mut Buffer, x: u16, y: u16, width: u16, style: Style) {
    for cell_x in x..x + width {
        if let Some(cell) = buf.cell_mut((cell_x, y)) {
            cell.set_style(style);
        }
    }
}

struct DisplayValue {
    text: String,
    cursor: usize,
}

fn compute_select_display(form: &CredentialForm, field: &FormField) -> DisplayValue {
    let icon = form.credential_type.icon();
    DisplayValue {
        text: format!("{} {}  [Space/Ctrl+Space]", icon, field.value),
        cursor: 0,
    }
}

fn compute_text_display(form: &CredentialForm, field: &FormField, value_width: usize) -> DisplayValue {
    let text = if field.masked && !form.show_password {
        "*".repeat(field.value.len())
    } else {
        field.value.clone()
    };

    let cursor_pos = form.cursor;
    let scroll = if cursor_pos >= value_width.saturating_sub(1) {
        cursor_pos.saturating_sub(value_width.saturating_sub(2))
    } else {
        0
    };

    let visible: String = text.chars().skip(scroll).take(value_width).collect();
    let adjusted_cursor = cursor_pos.saturating_sub(scroll);

    DisplayValue {
        text: visible,
        cursor: adjusted_cursor,
    }
}

fn value_style(field: &FormField, is_active: bool) -> Style {
    let bg = if is_active { Color::DarkGray } else { Color::Black };
    let fg = match field.field_type {
        FieldType::Select => Color::Yellow,
        _ if field.masked => Color::Green,
        _ => Color::White,
    };
    Style::default().fg(fg).bg(bg)
}

fn render_cursor(buf: &mut Buffer, x: u16, y: u16, max_x: u16) {
    if x >= max_x {
        return;
    }
    if let Some(cell) = buf.cell_mut((x, y)) {
        cell.set_style(Style::default().bg(Color::White).fg(Color::Black));
    }
}

fn render_field(
    buf: &mut Buffer,
    form: &CredentialForm,
    field: &FormField,
    field_idx: usize,
    inner: &Rect,
    y: u16,
    label_width: u16,
) {
    let is_active = field_idx == form.active_field;

    let label = format_label(field);
    buf.set_string(inner.x, y, &label, label_style(is_active));

    let value_x = inner.x + label_width;
    let value_width = inner.width.saturating_sub(label_width + 1);

    fill_field_background(buf, value_x, y, value_width, field_background_style(is_active));

    let display = if field.field_type == FieldType::Select {
        compute_select_display(form, field)
    } else {
        compute_text_display(form, field, value_width as usize)
    };

    buf.set_string(value_x, y, &display.text, value_style(field, is_active));

    if is_active && field.field_type != FieldType::Select {
        render_cursor(buf, value_x + display.cursor as u16, y, value_x + value_width);
    }
}

fn render_help_text(buf: &mut Buffer, inner: &Rect) {
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

impl<'a> Widget for CredentialFormWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let form_area = calculate_form_area(area);
        let inner = render_form_block(buf, form_area, self.title);

        let label_width = 18u16;
        let visible_height = inner.height.saturating_sub(1);
        let max_visible_fields = (visible_height / 2) as usize;

        let needs_scrolling = self.form.fields.len() > max_visible_fields;
        let scroll_offset = if needs_scrolling { self.form.scroll_offset } else { 0 };

        let has_up_indicator = needs_scrolling && scroll_offset > 0;
        let mut y = if has_up_indicator { inner.y + 1 } else { inner.y };

        if has_up_indicator {
            render_scroll_indicator(buf, &inner, true);
        }

        for (i, field) in self.form.fields.iter().enumerate().skip(scroll_offset) {
            if i >= scroll_offset + max_visible_fields { break; }
            render_field(buf, self.form, field, i, &inner, y, label_width);
            y += 2;
        }

        if needs_scrolling && scroll_offset + max_visible_fields < self.form.fields.len() {
            render_scroll_indicator(buf, &inner, false);
        }

        render_help_text(buf, &inner);
    }
}
