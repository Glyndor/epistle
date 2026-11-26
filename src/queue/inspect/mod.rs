//! What an operator looks at and steers in the outbound queue, which
//! `epistle queue` and the `/api/v1/queue` routes both do: one entry as the
//! command shows it, the headers of its message, retry, hold and release, and
//! the destinations that hold the queue off.
//!
//! No function here prints. The command renders what they return as text and
//! the routes as JSON, so the two say the same thing.

use serde_json::{Value, json};
use uuid::Uuid;

use crate::storage::{Envelope, FsSpool};

mod destinations;
mod headers;
mod waiting;

pub use destinations::{Held, held, rows as destination_rows};
pub use headers::{Header, MAX_HEADERS, headers_of};
pub use waiting::{Waiting, json_rows, only_waits, waiting, waits};

/// A change to one entry's schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Steer {
	/// Make the next attempt happen now, skipping the backoff.
	Retry,
	/// Never attempt the entry until it is released.
	Hold,
	/// Let a held entry be attempted again.
	Release,
}

impl Steer {
	/// The word the command and the routes use for it.
	pub const fn name(self) -> &'static str {
		match self {
			Steer::Retry => "retry",
			Steer::Hold => "hold",
			Steer::Release => "release",
		}
	}
}

/// Who asks for a change: the operator, or a key confined to some domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
	/// The operator at a terminal, or a key with no confinement.
	Operator,
	/// A key confined to these domains, lowercased.
	Confined(Vec<String>),
}

impl Holder {
	/// Whether a hold put by `by` may be lifted by this holder: the operator
	/// lifts any, a confined key only one put by a key confined inside its own
	/// domains.
	pub fn may_lift(&self, by: Option<&[String]>) -> bool {
		match (self, by) {
			(Holder::Operator, _) => true,
			(Holder::Confined(own), Some(by)) => {
				!by.is_empty() && by.iter().all(|domain| own.contains(domain))
			}
			(Holder::Confined(_), None) => false,
		}
	}
}

/// Why a change was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
	/// The entry is being removed, and stays on hold until it is.
	Cancelling,
	/// The hold was put by the operator, or by a key outside this one's reach.
	HeldByOther,
}

/// An entry after a change, and whether the change altered it.
#[derive(Debug, Clone)]
pub struct Steered {
	/// The entry as it is now.
	pub envelope: Envelope,
	/// False when it already was as the change leaves it.
	pub changed: bool,
	/// Why nothing was done, when something was in the way.
	pub refused: Option<Refused>,
}

/// Apply `steer` for `by` to the entry `id`, as of `now`. The decision and the
/// write are one step under the spool's lock, which also serializes them
/// against the worker's own writes. A missing entry is `NotFound` and
/// nothing is written.
pub fn steer(
	spool: &FsSpool,
	id: Uuid,
	steer: Steer,
	by: &Holder,
	now: u64,
) -> std::io::Result<Steered> {
	let (mut changed, mut refused) = (false, None);
	let envelope = spool.update_envelope(id, |envelope| match steer {
		Steer::Retry => {
			changed = envelope.next_attempt != 0;
			envelope.next_attempt = 0;
		}
		Steer::Hold => {
			let own = match by {
				Holder::Operator => None,
				Holder::Confined(domains) => Some(domains.clone()),
			};
			changed = envelope.held.is_none()
				|| envelope.held_for_removal
				|| (own.is_none() && envelope.held_by.is_some());
			let was_held = envelope.has_real_hold();
			// The operator takes a hold over; a key does not take one from
			// another key or from the operator. A hold placed on an entry a
			// removal is holding is a hold of its own, and the removal
			// respects it.
			if !was_held || own.is_none() {
				envelope.held_by = own;
			}
			envelope.held_for_removal = false;
			envelope.hold(now);
		}
		Steer::Release => {
			if envelope.cancelling.is_some() {
				refused = Some(Refused::Cancelling);
			} else if envelope.held.is_some() && !by.may_lift(envelope.held_by.as_deref()) {
				refused = Some(Refused::HeldByOther);
			} else {
				changed = envelope.held.is_some();
				envelope.release(now);
			}
		}
	})?;
	Ok(Steered {
		envelope,
		changed,
		refused,
	})
}

/// One entry as `epistle queue show --json` prints it: the envelope and its
/// retry state, never the message.
pub fn show_view(envelope: &Envelope) -> Value {
	json!({
		"id": envelope.id,
		"reverse_path": envelope.reverse_path,
		"recipients": envelope.recipients,
		"attempts": envelope.attempts,
		"next_attempt": envelope.next_attempt,
		"held": envelope.held.is_some(),
		"held_since": envelope.held,
		"require_tls": envelope.require_tls,
		"last_error": envelope.last_error,
	})
}

#[cfg(test)]
mod tests;
