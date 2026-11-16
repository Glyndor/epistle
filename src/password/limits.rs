//! The length limits of the password policy (`[auth] min_password_length` and
//! `max_password_length`), process-wide.
//!
//! The policy is built in many places (CLI, management API, SCIM, `init`), so
//! the limits live here once and the loader installs them when it reads the
//! configuration. The defaults are the limits the server always had: 12 and 64.
//!
//! Two bounds hold whatever the operator writes. A password shorter than
//! [`MIN_FLOOR`] is too cheap to guess offline, whatever the hash. A maximum
//! below [`MAX_FLOOR`] would refuse passphrases that NIST SP 800-63B asks every
//! verifier to accept. The ceiling keeps the input of an argon2 hash bounded.

use std::sync::RwLock;

use super::{MAX_LENGTH, MIN_LENGTH};

/// The shortest minimum length the loader accepts.
pub const MIN_FLOOR: usize = 8;
/// The lowest maximum length the loader accepts: NIST SP 800-63B, 64 characters.
pub const MAX_FLOOR: usize = 64;
/// The highest maximum length the loader accepts.
pub const MAX_CEILING: usize = 1024;

/// The accepted password length, in characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Fewest characters a password may have.
	pub min: usize,
	/// Most characters a password may have.
	pub max: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			min: MIN_LENGTH,
			max: MAX_LENGTH,
		}
	}
}

impl Limits {
	/// Refuse limits below the floors, above the ceiling, or inverted.
	pub fn validate(self) -> Result<(), String> {
		if self.min < MIN_FLOOR {
			return Err(format!(
				"[auth] min_password_length ({}) must be at least {MIN_FLOOR}",
				self.min
			));
		}
		if self.max < MAX_FLOOR {
			return Err(format!(
				"[auth] max_password_length ({}) must be at least {MAX_FLOOR}: NIST SP 800-63B asks \
				 every verifier to accept passwords of that length",
				self.max
			));
		}
		if self.max > MAX_CEILING {
			return Err(format!(
				"[auth] max_password_length ({}) must be at most {MAX_CEILING}",
				self.max
			));
		}
		if self.min > self.max {
			return Err(format!(
				"[auth] min_password_length ({}) must not be above max_password_length ({})",
				self.min, self.max
			));
		}
		Ok(())
	}

	/// What a user is told when a password is outside the limits.
	pub(super) fn message(self) -> String {
		format!(
			"Password must be between {} and {} characters.",
			self.min, self.max
		)
	}
}

static CURRENT: RwLock<(Limits, &'static str)> = RwLock::new((
	Limits {
		min: MIN_LENGTH,
		max: MAX_LENGTH,
	},
	"Password must be between 12 and 64 characters.",
));

#[cfg(test)]
thread_local! {
	static SCOPED: std::cell::Cell<Option<Limits>> = const { std::cell::Cell::new(None) };
}

/// The limits in force.
pub fn current() -> Limits {
	#[cfg(test)]
	if let Some(scoped) = SCOPED.with(|cell| cell.get()) {
		return scoped;
	}
	CURRENT.read().unwrap_or_else(|p| p.into_inner()).0
}

/// The sentence that names the limits in force, for a rejected password.
pub fn message() -> &'static str {
	#[cfg(test)]
	if let Some(scoped) = SCOPED.with(|cell| cell.get()) {
		return Box::leak(scoped.message().into_boxed_str());
	}
	CURRENT.read().unwrap_or_else(|p| p.into_inner()).1
}

/// Run `body` with `limits` in force on this thread only, so a test of other
/// limits cannot reach the tests that run beside it.
#[cfg(test)]
pub(crate) fn scoped<R>(limits: Limits, body: impl FnOnce() -> R) -> R {
	struct Restore(Option<Limits>);
	impl Drop for Restore {
		fn drop(&mut self) {
			SCOPED.with(|cell| cell.set(self.0));
		}
	}
	let _restore = Restore(SCOPED.with(|cell| cell.replace(Some(limits))));
	body()
}

/// Put `limits` in force. Installing what is already in force changes nothing.
/// The message is built once per distinct limits and kept for the life of the
/// process, which is a few dozen bytes per configuration reload.
pub fn install(limits: Limits) {
	let mut current = CURRENT.write().unwrap_or_else(|p| p.into_inner());
	if current.0 != limits {
		*current = (limits, Box::leak(limits.message().into_boxed_str()));
	}
}
