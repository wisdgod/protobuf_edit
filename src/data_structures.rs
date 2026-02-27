//! Core storage building blocks shared by higher-level modules.
//!
//! `Buf` is the primary byte container used across `wire`, `stream`, and `document`.
pub mod buf;

pub use buf::{Buf, BufAllocError};
