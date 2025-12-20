//! UI Module
//!
//! Terminal user interface using ratatui.

pub mod components;
pub mod renderer;

// Re-exports
pub use components::{
    ConfirmDialog, CredentialDetail, CredentialForm, CredentialFormWidget, CredentialItem,
    CredentialList, DetailView, EmptyState, HelpBar, HelpScreen, ListViewState, MessageType,
    PasswordDialog, StatusLine,
};
pub use renderer::{PasswordPrompt, Renderer, UiState, View};
