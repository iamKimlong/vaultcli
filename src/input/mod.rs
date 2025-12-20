//! Input Module
//!
//! Handles keyboard input with vim-style modal editing.

pub mod handler;
pub mod keymap;
pub mod modes;

// Re-exports
pub use handler::InputHandler;
pub use keymap::Action;
pub use modes::{InputMode, ModeState};
