//! UI Components
//!
//! Reusable TUI widgets for the credential manager.

pub mod detail;
pub mod form;
pub mod list;
pub mod popup;
pub mod statusline;

// Re-exports
pub use detail::{CredentialDetail, DetailView};
pub use form::{CredentialForm, CredentialFormWidget, FormField};
pub use list::{CredentialItem, CredentialList, EmptyState, ListViewState};
pub use popup::{centered_rect, centered_rect_fixed, ConfirmDialog, HelpScreen, PasswordDialog};
pub use statusline::{HelpBar, MessageType, StatusLine};
