//! What the book holds: an account's counts, the outcomes a message still
//! owes, and the book itself.

use std::time::Instant;

use super::state::State;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Held {
	pub(crate) records: u64,
	pub(crate) bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Owed {
	pub(super) left: u64,
	pub(super) day: i64,
	pub(super) account: String,
}

#[derive(Debug)]
pub(super) struct Book {
	pub(super) state: State,
	/// Whether the book was rebuilt from the log yet.
	pub(super) loaded: bool,
	/// Why the book could not be rebuilt, while it cannot: acceptances wait.
	pub(super) unavailable: Option<String>,
	pub(super) tried: Option<Instant>,
}
