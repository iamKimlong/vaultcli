//! Renderer
//!
//! Main rendering logic for the application.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders},
    Frame,
};

use super::components::{
    ConfirmDialog, CredentialDetail, CredentialForm, CredentialFormWidget, CredentialItem,
    CredentialList, DetailView, EmptyState, HelpBar, HelpScreen, ListViewState, MessageType,
    PasswordDialog, StatusLine,
};
use crate::input::InputMode;

/// Current view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    List,
    Detail,
    Form,
}

/// UI state for rendering
pub struct UiState<'a> {
    pub view: View,
    pub mode: InputMode,
    pub credentials: &'a [CredentialItem],
    pub list_state: &'a mut ListViewState,
    pub selected_detail: Option<&'a CredentialDetail>,
    pub command_buffer: Option<&'a str>,
    pub message: Option<(&'a str, MessageType)>,
    pub confirm_message: Option<&'a str>,
    pub password_prompt: Option<PasswordPrompt<'a>>,
    pub project_name: Option<&'a str>,
    pub credential_form: Option<&'a CredentialForm>,
}

pub struct PasswordPrompt<'a> {
    pub title: &'a str,
    pub prompt: &'a str,
    pub value: &'a str,
    pub cursor: usize,
    pub error: Option<&'a str>,
}

/// Main renderer
pub struct Renderer;

impl Renderer {
    pub fn render(frame: &mut Frame, state: &mut UiState) {
        let size = frame.area();

        // Main layout: content + status + help
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(size);

        let content_area = chunks[0];
        let status_area = chunks[1];
        let help_area = chunks[2];

        // Render main content
        match state.view {
            View::List => Self::render_list(frame, content_area, state),
            View::Detail => Self::render_detail(frame, content_area, state),
            View::Form => Self::render_form(frame, content_area, state),
        }

        // Render status line
        let mut status = StatusLine::new(state.mode);
        
        if let Some(buffer) = state.command_buffer {
            status = status.command_buffer(buffer);
        } else if let Some((msg, msg_type)) = state.message {
            status = status.message(msg, msg_type);
        }

        if let Some(project) = state.project_name {
            status = status.project_name(project);
        }

        if let Some(selected) = state.list_state.selected() {
            status = status.item_count(selected, state.list_state.total);
        }

        frame.render_widget(status, status_area);

        // Render help bar
        let help_bar = HelpBar::for_mode(state.mode);
        frame.render_widget(help_bar, help_area);

        // Render overlays
        Self::render_overlays(frame, size, state);
    }

    fn render_list(frame: &mut Frame, area: Rect, state: &mut UiState) {
        if state.credentials.is_empty() {
            let empty = EmptyState::new("No credentials")
                .hint("Press 'n' to add one");
            frame.render_widget(empty, area);
        } else {
            let block = Block::default()
                .title(" Credentials ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan));

            let list = CredentialList::new(state.credentials).block(block);
            frame.render_stateful_widget(list, area, state.list_state);
        }
    }

    fn render_detail(frame: &mut Frame, area: Rect, state: &mut UiState) {
        // Split into list and detail
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // List on left
        let block = Block::default()
            .title(" Credentials ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let list = CredentialList::new(state.credentials).block(block);
        frame.render_stateful_widget(list, chunks[0], state.list_state);

        // Detail on right
        if let Some(detail) = state.selected_detail {
            let detail_view = DetailView::new(detail);
            frame.render_widget(detail_view, chunks[1]);
        } else {
            let empty = EmptyState::new("Select a credential");
            frame.render_widget(empty, chunks[1]);
        }
    }

    fn render_form(frame: &mut Frame, area: Rect, state: &mut UiState) {
        if let Some(form) = state.credential_form {
            let form_widget = CredentialFormWidget::new(form);
            frame.render_widget(form_widget, area);
        } else {
            // Fallback - shouldn't happen
            let block = Block::default()
                .title(" Form ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green));
            frame.render_widget(block, area);
        }
    }

    fn render_overlays(frame: &mut Frame, area: Rect, state: &mut UiState) {
        // Help screen
        if state.mode == InputMode::Help {
            frame.render_widget(HelpScreen, area);
            return;
        }

        // Confirm dialog
        if state.mode == InputMode::Confirm {
            if let Some(msg) = state.confirm_message {
                let dialog = ConfirmDialog::new(" Confirm ", msg);
                frame.render_widget(dialog, area);
            }
            return;
        }

        // Password dialog
        if let Some(ref prompt) = state.password_prompt {
            let mut dialog = PasswordDialog::new(prompt.title, prompt.prompt, prompt.value, prompt.cursor);
            if let Some(err) = prompt.error {
                dialog = dialog.error(err);
            }
            frame.render_widget(dialog, area);
        }
    }
}
