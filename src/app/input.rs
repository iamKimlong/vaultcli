use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::input::keymap::{confirm_action, normal_mode_action, text_input_action, Action};
use crate::input::modes::InputMode;
use crate::ui::components::popup::{HelpScreen, LogsScreen, TagsPopup};
use crate::ui::components::{CredentialForm, MessageType};
use crate::ui::renderer::View;

use super::App;

type KeyHandler = fn(&mut App, KeyCode, KeyModifiers) -> Option<Action>;

impl App {
    pub fn handle_key_event(&mut self, key: KeyEvent) -> Result<bool, Box<dyn std::error::Error>> {
        if key.kind != KeyEventKind::Press {
            return Ok(false);
        }

        if self.view == View::Form && self.credential_form.is_some() {
            return self.handle_form_key(key);
        }

        let action = self.resolve_action(key);
        self.execute_action(action)
    }

    fn resolve_action(&mut self, key: KeyEvent) -> Action {
        match self.mode_state.mode {
            InputMode::Normal => self.resolve_normal_action(key),
            InputMode::Command | InputMode::Search => self.resolve_text_action(key),
            InputMode::Confirm => confirm_action(key),
            InputMode::Help => self.popup_action(key, help_key_handler),
            InputMode::Logs => self.popup_action(key, logs_key_handler),
            InputMode::Tags => self.popup_action(key, tags_key_handler),
            _ => Action::None,
        }
    }

    fn resolve_normal_action(&mut self, key: KeyEvent) -> Action {
        let (action, pending) = normal_mode_action(key, self.mode_state.pending);
        self.mode_state.pending = pending;
        action
    }

    fn resolve_text_action(&mut self, key: KeyEvent) -> Action {
        let action = text_input_action(key);
        self.handle_text_input(action)
    }

    fn popup_action(&mut self, key: KeyEvent, handler: KeyHandler) -> Action {
        self.handle_popup_key(key, handler);
        Action::None
    }

    fn handle_popup_key(&mut self, key: KeyEvent, handler: KeyHandler) {
        if let Some(action) = handler(self, key.code, key.modifiers) {
            let _ = self.execute_action(action);
        }
    }

    fn handle_text_input(&mut self, action: Action) -> Action {
        match action {
            Action::InsertChar(c) => { self.mode_state.insert_char(c); Action::None }
            Action::DeleteChar => { self.mode_state.delete_char(); Action::None }
            Action::CursorLeft => { self.mode_state.cursor_left(); Action::None }
            Action::CursorRight => { self.mode_state.cursor_right(); Action::None }
            Action::CursorHome => { self.mode_state.cursor_home(); Action::None }
            Action::CursorEnd => { self.mode_state.cursor_end(); Action::None }
            Action::ClearLine => { self.mode_state.clear_buffer(); Action::None }
            Action::Submit => self.submit_text_input(),
            Action::Cancel => { self.mode_state.to_normal(); Action::None }
            _ => action,
        }
    }

    fn submit_text_input(&mut self) -> Action {
        let buffer = self.mode_state.get_buffer().to_string();
        let result = match self.mode_state.mode {
            InputMode::Command => Action::ExecuteCommand(buffer),
            InputMode::Search => Action::Search(buffer),
            _ => Action::None,
        };
        self.mode_state.to_normal();
        result
    }

    fn handle_form_key(&mut self, key: KeyEvent) -> Result<bool, Box<dyn std::error::Error>> {
        let form = self.credential_form.as_mut().unwrap();
        let return_to = form.previous_view.clone();

        if key.code == KeyCode::Esc {
            self.credential_form = None;
            self.view = return_to;
            return Ok(false);
        }

        if key.code == KeyCode::Enter && key.modifiers == KeyModifiers::NONE {
            return self.submit_form();
        }

        let form = self.credential_form.as_mut().unwrap();

        dispatch_form_key(form, key.code, key.modifiers);
        Ok(false)
    }

    fn submit_form(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let form = self.credential_form.as_ref().unwrap();
        if let Err(e) = form.validate() {
            self.set_message(&e, MessageType::Error);
        } else {
            self.save_credential_form()?;
        }
        Ok(false)
    }
}

fn dispatch_form_key(form: &mut CredentialForm, code: KeyCode, mods: KeyModifiers) {
    match (code, mods) {
        (KeyCode::Tab, KeyModifiers::NONE) | (KeyCode::Down, _) => form.next_field(),
        (KeyCode::BackTab, _) | (KeyCode::Up, _) => form.prev_field(),
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => form.toggle_password_visibility(),
        (KeyCode::Char(' '), m) if form.is_select_field() => form.cycle_type(m != KeyModifiers::CONTROL),
        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => form.insert_char(c),
        (KeyCode::Backspace, _) => form.delete_char(),
        (KeyCode::Left, _) => form.cursor_left(),
        (KeyCode::Right, _) => form.cursor_right(),
        _ => {}
    }
}

fn help_key_handler(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    match (code, mods) {
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT)
        | (KeyCode::Char('q'), KeyModifiers::NONE)
        | (KeyCode::Esc, _) => {
            app.mode_state.to_normal();
            return None;
        }
        (KeyCode::Char('i'), KeyModifiers::NONE) => return Some(Action::ShowLogs),
        (KeyCode::Char('t'), KeyModifiers::NONE) => return Some(Action::ShowTags),
        _ => {}
    }

    let was_pending = app.help_state.scroll.pending_g;
    app.help_state.scroll.pending_g = false;

    let size = app.terminal_size;
    let visible = HelpScreen::visible_height(size) as usize;
    let max_v = HelpScreen::max_scroll(size);
    let max_h = HelpScreen::max_h_scroll(size);

    match (code, mods) {
        (KeyCode::Char('g'), KeyModifiers::NONE) if was_pending => app.help_state.home(),
        (KeyCode::Char('g'), KeyModifiers::NONE) => app.help_state.scroll.pending_g = true,
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => app.help_state.scroll_down(1, max_v),
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => app.help_state.scroll_up(1),
        (KeyCode::Char('G'), KeyModifiers::SHIFT) => app.help_state.end(max_v),
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => app.help_state.page_down(visible / 2, max_v),
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => app.help_state.page_up(visible / 2),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => app.help_state.page_down(visible.saturating_sub(1), max_v),
        (KeyCode::Char('b'), KeyModifiers::CONTROL) => app.help_state.page_up(visible.saturating_sub(1)),
        (KeyCode::Char('h'), KeyModifiers::NONE) | (KeyCode::Left, _) => app.help_state.scroll_left(5),
        (KeyCode::Char('l'), KeyModifiers::NONE) | (KeyCode::Right, _) => app.help_state.scroll_right(5, max_h),
        (KeyCode::Char('0'), KeyModifiers::NONE) => app.help_state.h_home(),
        (KeyCode::Char('$'), _) => app.help_state.h_end(max_h),
        _ => {}
    }

    None
}

fn logs_key_handler(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    let size = app.terminal_size;
    let state = &mut app.logs_state;

    match (code, mods) {
        (KeyCode::Char('i'), KeyModifiers::NONE)
        | (KeyCode::Char('q'), KeyModifiers::NONE)
        | (KeyCode::Esc, _) => {
            app.mode_state.to_normal();
            return None;
        }
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT) => return Some(Action::ShowHelp),
        (KeyCode::Char('t'), KeyModifiers::NONE) => return Some(Action::ShowTags),
        _ => {}
    }

    let was_pending = state.scroll.pending_g;
    state.scroll.pending_g = false;

    let visible = LogsScreen::visible_height(size) as usize;
    let max_v = state.max_scroll(visible as u16);
    let visible_width = LogsScreen::visible_width(size);
    let max_h = state.max_h_scroll(visible_width);

    match (code, mods) {
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => state.scroll_down(1, max_v),
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => state.scroll_up(1),
        (KeyCode::Char('g'), KeyModifiers::NONE) if was_pending => state.home(),
        (KeyCode::Char('g'), KeyModifiers::NONE) => state.scroll.pending_g = true,
        (KeyCode::Char('G'), KeyModifiers::SHIFT) => state.end(max_v),
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => state.page_down(visible / 2, max_v),
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => state.page_up(visible / 2),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => state.page_down(visible.saturating_sub(1), max_v),
        (KeyCode::Char('b'), KeyModifiers::CONTROL) => state.page_up(visible.saturating_sub(1)),
        (KeyCode::Char('h'), KeyModifiers::NONE) | (KeyCode::Left, _) => state.scroll_left(5),
        (KeyCode::Char('l'), KeyModifiers::NONE) | (KeyCode::Right, _) => state.scroll_right(5, max_h),
        (KeyCode::Char('0'), KeyModifiers::NONE) => state.h_home(),
        (KeyCode::Char('$'), _) => state.h_end(max_h),
        _ => {}
    }

    None
}

fn tags_key_handler(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    let size = app.terminal_size;
    let state = &mut app.tags_state;

    match (code, mods) {
        (KeyCode::Char('t'), KeyModifiers::NONE)
        | (KeyCode::Char('q'), KeyModifiers::NONE)
        | (KeyCode::Esc, _) => {
            app.mode_state.to_normal();
            return None;
        }
        (KeyCode::Char('?'), KeyModifiers::NONE | KeyModifiers::SHIFT) => return Some(Action::ShowHelp),
        (KeyCode::Char('i'), KeyModifiers::NONE) => return Some(Action::ShowLogs),
        _ => {}
    }

    let was_pending = state.scroll.pending_g;
    state.scroll.pending_g = false;

    let visible = TagsPopup::visible_height(size) as usize;

    match (code, mods) {
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, _) => state.scroll_down(),
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, _) => state.scroll_up(),
        (KeyCode::Char('g'), KeyModifiers::NONE) if was_pending => state.home(),
        (KeyCode::Char('g'), KeyModifiers::NONE) => state.scroll.pending_g = true,
        (KeyCode::Char('G'), KeyModifiers::SHIFT) => state.end(),
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => state.page_down(visible / 2),
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => state.page_up(visible / 2),
        (KeyCode::Char('f'), KeyModifiers::CONTROL) => state.page_down(visible.saturating_sub(1)),
        (KeyCode::Char('b'), KeyModifiers::CONTROL) => state.page_up(visible.saturating_sub(1)),
        (KeyCode::Char(' '), KeyModifiers::NONE) => {
            state.toggle_selected();
            state.scroll_down();
        }
        (KeyCode::Enter, _) | (KeyCode::Char('l'), KeyModifiers::NONE) => {
            return handle_tags_select(app);
        }
        _ => {}
    }

    None
}

fn handle_tags_select(app: &mut App) -> Option<Action> {
    let tags = if app.tags_state.has_selection() {
        app.tags_state.get_selected_tags()
    } else {
        app.tags_state.selected_tag().map(|t| vec![t.to_string()]).unwrap_or_default()
    };

    if tags.is_empty() {
        return None;
    }

    app.mode_state.to_normal();
    let _ = app.filter_by_tag(&tags);
    None
}

// Helper trait for CredentialForm
impl crate::ui::components::CredentialForm {
    pub fn is_select_field(&self) -> bool {
        self.active_field().field_type == crate::ui::components::form::FieldType::Select
    }
}
