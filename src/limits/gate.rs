//! A cap check a store runs under its own lock: the limits, whose count it
//! is and the scopes that reach it, carried to the place where the count and
//! the insert happen together.

use std::sync::Arc;

use super::{Kind, LimitReached, Limits, Target};

/// The caps of one account or domain, ready to be asked inside a store's
/// locked write. Counting and inserting under one lock is what makes the cap
/// hold when several writers race for the last place.
#[derive(Clone, Debug, Default)]
pub struct Gate {
	limits: Arc<Limits>,
	target: Target,
	subject: String,
}

impl Gate {
	/// The gate of `target`, reported as `subject` (`account alice`).
	pub fn new(limits: Arc<Limits>, target: Target, subject: String) -> Self {
		Self {
			limits,
			target,
			subject,
		}
	}

	/// Whether one more of `kind` fits when `current` exist already.
	pub fn admit(&self, kind: Kind, current: usize) -> Result<(), LimitReached> {
		self.limits
			.admit(kind, &self.target, current, &self.subject)
	}

	/// Whether `total` of `kind` fit.
	pub fn admit_total(&self, kind: Kind, total: usize) -> Result<(), LimitReached> {
		self.limits
			.admit_total(kind, &self.target, total, &self.subject)
	}

	/// The scopes of the gate, for a decision a caller makes itself.
	pub fn limits(&self) -> &Limits {
		&self.limits
	}

	/// The target of the gate.
	pub fn target(&self) -> &Target {
		&self.target
	}
}
