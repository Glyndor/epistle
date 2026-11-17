//! The refusal of an action that would pass a cap.

use super::{Cap, Kind};

/// A cap that stopped an action: which one, its value, whose it is and how
/// to make room. The text is the answer on every surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitReached {
	/// The thing that is capped.
	pub kind: Kind,
	/// The cap in force and the scope that set it.
	pub cap: Cap,
	/// Whose count reached it: `account alice`, `domain example.org`.
	pub subject: String,
	/// How many there are now; for a message, its size in bytes.
	pub current: u64,
}

impl LimitReached {
	/// The setting a larger cap is asked for, with the scope that holds it.
	pub fn setting(&self) -> String {
		format!("{} of {}", self.kind.key(), self.cap.set_by)
	}
}

impl LimitReached {
	/// The kind of scope that set the cap (`server`, `tenant`, `domain` or
	/// `account`), without its name.
	pub fn scope_kind(&self) -> &str {
		self.cap
			.set_by
			.split_whitespace()
			.next()
			.map(|word| if word == "the" { "server" } else { word })
			.unwrap_or("server")
	}

	/// Write the refusal to the log for `account`: the pseudonym of the
	/// account and structured fields that name no one. The text of the
	/// refusal carries names and is for the person refused, not for the log.
	pub fn log(&self, account: &str) {
		tracing::info!(
			account = %crate::log_id::account(account),
			limit = self.kind.key(),
			cap = self.cap.value,
			scope = self.scope_kind(),
			current = self.current,
			"limit reached"
		);
	}
}

impl std::fmt::Display for LimitReached {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.kind == Kind::MessageSize {
			return write!(
				f,
				"message of {} bytes exceeds the limit of {} bytes for {} (set by {}); {}, or ask the operator to raise {}",
				self.current,
				self.cap.value,
				self.subject,
				self.cap.set_by,
				self.kind.how_to_free_room(),
				self.kind.key(),
			);
		}
		write!(
			f,
			"{} is at the limit of {} {} (set by {}); to make room {}, or ask the operator to raise {}",
			self.subject,
			self.cap.value,
			self.kind.noun(),
			self.cap.set_by,
			self.kind.how_to_free_room(),
			self.kind.key(),
		)
	}
}

impl std::error::Error for LimitReached {}
