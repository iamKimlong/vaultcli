//! Input Module
//!
//! Handles keyboard input with vim-style modal editing.

pub mod keymap;
pub mod modes;

// Re-exports
pub use modes::{InputMode};
