//! The DKIM, ARC and reverse-DNS checks of a scope: whether each one only
//! annotates or refuses. The most specific scope in reach wins for one
//! recipient, and a message for several recipients gets the strictest
//! setting any of them has.

use super::{Scopes, Target};
use crate::config::{CheckPolicy, CheckScope};

/// What the checks do for one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
	/// DKIM: `Off` and `Annotate` are the same, DMARC needs the result.
	pub dkim: CheckPolicy,
	/// Whether `dkim = reject` also refuses a message with no passing
	/// signature, whoever sent it.
	pub dkim_require_signature: bool,
	/// ARC chain validation.
	pub arc: CheckPolicy,
	/// Reverse DNS of the connecting address.
	pub reverse_dns: CheckPolicy,
}

impl Default for Checks {
	/// What the server does with no scope: DKIM is recorded, ARC and the
	/// reverse DNS are not looked at.
	fn default() -> Self {
		Self {
			dkim: CheckPolicy::Annotate,
			dkim_require_signature: false,
			arc: CheckPolicy::Off,
			reverse_dns: CheckPolicy::Off,
		}
	}
}

impl Checks {
	/// `self` with the keys `scope` sets on top.
	fn apply(self, scope: &CheckScope) -> Self {
		Self {
			dkim: scope.dkim.unwrap_or(self.dkim),
			dkim_require_signature: scope
				.dkim_require_signature
				.unwrap_or(self.dkim_require_signature),
			arc: scope.arc.unwrap_or(self.arc),
			reverse_dns: scope.reverse_dns.unwrap_or(self.reverse_dns),
		}
	}

	/// The stricter of two: `reject` over `annotate` over `off`.
	fn stricter(self, other: Self) -> Self {
		Self {
			dkim: self.dkim.max(other.dkim),
			dkim_require_signature: self.dkim_require_signature || other.dkim_require_signature,
			arc: self.arc.max(other.arc),
			reverse_dns: self.reverse_dns.max(other.reverse_dns),
		}
	}
}

impl Scopes {
	/// The checks for mail to `targets`: the scopes of each target applied
	/// widest first, then the strictest of the targets.
	pub fn checks(&self, targets: &[Target]) -> Checks {
		let mut merged: Option<Checks> = None;
		for target in targets {
			let checks = self
				.layers(target)
				.fold(Checks::default(), |checks, layer| {
					checks.apply(&layer.checks)
				});
			merged = Some(match merged {
				Some(seen) => seen.stricter(checks),
				None => checks,
			});
		}
		merged.unwrap_or_default()
	}
}
