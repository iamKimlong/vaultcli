//! List View Component
//!
//! Displays credentials in a scrollable list.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget},
};

use crate::db::models::CredentialType;

/// Credential display item
#[derive(Debug, Clone)]
pub struct CredentialItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub credential_type: CredentialType,
    pub tags: Vec<String>,
}

/// List view state
#[derive(Debug, Clone)]
pub struct ListViewState {
    /// Selected index
    pub selected: Option<usize>,
    /// Total items
    pub total: usize,
    /// Scroll offset
    pub offset: usize,
    /// Current search query
    pub search: Option<String>,
    /// Internal list state for ratatui
    list_state: ListState,
}

impl Default for ListViewState {
    fn default() -> Self {
        Self {
            selected: None,
            total: 0,
            offset: 0,
            search: None,
            list_state: ListState::default(),
        }
    }
}

impl ListViewState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
        self.list_state.select(index);
    }

    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    pub fn set_total(&mut self, total: usize) {
        self.total = total;
        if let Some(sel) = self.selected {
            if sel >= total && total > 0 {
                self.select(Some(total - 1));
            } else if total == 0 {
                self.select(None);
            }
        } else if total > 0 {
            self.select(Some(0));
        }
    }

    pub fn move_up(&mut self) {
        if self.total == 0 {
            return;
        }
        let new_index = self.selected.unwrap_or(0).saturating_sub(1);
        self.select(Some(new_index));
    }

    pub fn move_down(&mut self) {
        if self.total == 0 {
            return;
        }
        let new_index = self.selected.map_or(0, |i| (i + 1).min(self.total - 1));
        self.select(Some(new_index));
    }

    pub fn move_to_top(&mut self) {
        if self.total > 0 {
            self.select(Some(0));
        }
    }

    pub fn move_to_bottom(&mut self) {
        if self.total > 0 {
            self.select(Some(self.total - 1));
        }
    }

    pub fn page_up(&mut self, page_size: usize) {
        if self.total == 0 {
            return;
        }
        let new_index = match self.selected {
            Some(i) => i.saturating_sub(page_size),
            None => 0,
        };
        self.select(Some(new_index));
    }

    pub fn page_down(&mut self, page_size: usize) {
        if self.total == 0 {
            return;
        }
        let new_index = match self.selected {
            Some(i) => (i + page_size).min(self.total - 1),
            None => 0,
        };
        self.select(Some(new_index));
    }

    pub fn list_state_mut(&mut self) -> &mut ListState {
        &mut self.list_state
    }
}

/// Credential list widget
pub struct CredentialList<'a> {
    items: &'a [CredentialItem],
    block: Option<Block<'a>>,
    highlight_style: Style,
    show_username: bool,
}

impl<'a> CredentialList<'a> {
    pub fn new(items: &'a [CredentialItem]) -> Self {
        Self {
            items,
            block: None,
            highlight_style: Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
            show_username: true,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn highlight_style(mut self, style: Style) -> Self {
        self.highlight_style = style;
        self
    }

    pub fn show_username(mut self, show: bool) -> Self {
        self.show_username = show;
        self
    }
}

impl<'a> StatefulWidget for CredentialList<'a> {
    type State = ListViewState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let selected = state.selected();

        let items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let is_selected = Some(i) == selected;
            
                let symbol = if is_selected {
                    Span::styled(" ", Style::default()
                        .fg(Color::Magenta)
                        .bg(Color::DarkGray))
                } else {
                    Span::raw("  ")
                };

                let icon = item.credential_type.icon();
                let type_color = type_color(item.credential_type);

                let base_style = if is_selected {
                    self.highlight_style
                } else {
                    Style::default()
                };

                let mut spans = vec![
                    symbol,
                    Span::styled(format!("{} ", icon), base_style.fg(type_color)),
                    Span::styled(&item.name, base_style.fg(Color::White)),
                ];

                if self.show_username {
                    if let Some(ref username) = item.username {
                        spans.push(Span::styled(
                            format!(" ({})", username),
                            base_style.fg(Color::Cyan),
                        ));
                    }
                }

                let mut list_item = ListItem::new(Line::from(spans));
                if is_selected {
                    list_item = list_item.style(self.highlight_style);
                }
                list_item
            })
            .collect();

        let list = List::new(items);
        let list = if let Some(block) = self.block {
            list.block(block)
        } else {
            list
        };

        StatefulWidget::render(list, area, buf, state.list_state_mut());
    }
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

/// Empty state widget
pub struct EmptyState<'a> {
    message: &'a str,
    hint: Option<&'a str>,
}

impl<'a> EmptyState<'a> {
    pub fn new(message: &'a str) -> Self {
        Self {
            message,
            hint: None,
        }
    }

    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = Some(hint);
        self
    }
}

impl<'a> Widget for EmptyState<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let center_y = area.y + area.height / 2;

        // Message
        let msg_x = area.x + (area.width.saturating_sub(self.message.len() as u16)) / 2;
        buf.set_string(
            msg_x,
            center_y,
            self.message,
            Style::default().fg(Color::DarkGray),
        );

        // Hint
        if let Some(hint) = self.hint {
            let hint_x = area.x + (area.width.saturating_sub(hint.len() as u16)) / 2;
            buf.set_string(
                hint_x,
                center_y + 1,
                hint,
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_state_navigation() {
        let mut state = ListViewState::new();
        state.set_total(5);

        assert_eq!(state.selected(), Some(0));

        state.move_down();
        assert_eq!(state.selected(), Some(1));

        state.move_up();
        assert_eq!(state.selected(), Some(0));

        state.move_to_bottom();
        assert_eq!(state.selected(), Some(4));

        state.move_to_top();
        assert_eq!(state.selected(), Some(0));
    }

    #[test]
    fn test_list_state_empty() {
        let mut state = ListViewState::new();
        state.set_total(0);

        state.move_down();
        assert_eq!(state.selected(), None);
    }
}
