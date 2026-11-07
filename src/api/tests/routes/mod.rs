//! The HTTP routes every deployment answers.

pub use super::*;

pub(super) mod core;
pub(super) mod queue;
pub(super) mod send;
pub(super) mod suppression;
pub(super) mod tokens;
