//! Backing off a destination that asks the queue to slow down.
//!
//! Large receivers answer a sender that goes too fast with a 421 (often at
//! the greeting), a 4.7.x status, or a 451 or 452 that says the sender hit a
//! rate limit. Retrying each message on its own schedule would keep hitting
//! them; instead the recipients that got such a reply wait for the next
//! step of the backoff (1, 5, 15 and 60 minutes by default), and every
//! other message to the same destination waits with them.
//!
//! The spool is the only record of it. A recipient deferred that way keeps
//! its `next_attempt` at the end of the wait and counts its deferrals in a
//! row in `throttled`, which only goes back to zero when the recipient gets
//! another answer. A destination, the recipient domain or the exchanger host
//! that asked (a provider that hosts many domains limits the sender on its
//! own hosts), is on hold while any pending recipient deferred by it still
//! waits. [`Holds`] reads that from the spool; it holds nothing the spool
//! does not, and the worker rebuilds it at every scan.
//!
//! A `452 4.5.3` (too many recipients) is different: the remote took some
//! recipients and asks for the rest in another transaction. Those are not
//! failures and are retried at once, not held off.

use crate::queue::reply::parse_enhanced;
use std::collections::HashMap;

use super::destination::Destination;
use crate::storage::{Envelope, RecipientStatus};

/// The default backoff, in seconds: 1, 5, 15 and 60 minutes.
pub const DEFAULT_STEPS: [u64; 4] = [60, 300, 900, 3600];
/// The most steps the configuration accepts.
pub const MAX_STEPS: usize = 16;
/// The longest step the configuration accepts: one day.
pub const MAX_STEP_SECS: u64 = 86_400;

/// A stored reason read as a reply: its code, the subject and detail of
/// its enhanced status when it has one, and its text in lower case.
type ReadReply = (u16, Option<(u16, u16)>, String);

/// The reply code and enhanced status at the head of a stored reason
/// (`452 4.5.3 ...`), when it has them.
fn code_of(reason: &str) -> Option<ReadReply> {
	let code: u16 = reason
		.get(..3)
		.filter(|head| head.bytes().all(|b| b.is_ascii_digit()))?
		.parse()
		.ok()?;
	let rest = reason.get(3..).unwrap_or_default().trim_start();
	let enhanced = rest
		.split_whitespace()
		.next()
		.and_then(parse_enhanced)
		.filter(|enhanced| enhanced.class == code / 100)
		.map(|enhanced| (enhanced.subject, enhanced.detail));
	Some((code, enhanced, rest.to_ascii_lowercase()))
}

/// Whether `reason` says the transaction had too many recipients
/// (`452 4.5.3`, RFC 5321 section 4.5.3.1.10): the rest are to be sent in
/// another transaction.
pub fn too_many_recipients(reason: &str) -> bool {
	match code_of(reason) {
		Some((452, Some((5, 3)), _)) => true,
		Some((452, None, text)) => text.contains("too many recipients"),
		_ => false,
	}
}

/// Whether `reason` asks the sender to slow down: any 421, any 4.7.x, or a
/// 451 or 452 whose text speaks of a rate or a limit.
pub fn throttled(reason: &str) -> bool {
	if too_many_recipients(reason) {
		return false;
	}
	let Some((code, enhanced, text)) = code_of(reason) else {
		return false;
	};
	match (code, enhanced) {
		(421, _) => true,
		(400..=499, Some((7, _))) => true,
		(451 | 452, _) => ["rate", "throttl", "too many", "slow down", "limit"]
			.iter()
			.any(|word| text.contains(word)),
		_ => false,
	}
}

/// The wait after `level` slow-down deferrals in a row: the step at that
/// position, the last one repeating.
pub fn step(steps: &[u64], level: u32) -> u64 {
	steps
		.get(level as usize)
		.or(steps.last())
		.copied()
		.unwrap_or(DEFAULT_STEPS[0])
}

/// A destination on hold, as the spool shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
	/// Epoch seconds until which the destination is not contacted.
	pub until: u64,
	/// The most slow-down deferrals in a row of any recipient waiting for
	/// it: the next deferral takes the step after.
	pub deferrals: u32,
	/// The reply that asked to slow down, of the recipient waiting longest.
	pub reason: String,
}

/// Every destination with a recipient waiting after a slow-down reply,
/// read from the spool. It keeps nothing of its own: dropping it and
/// reading it again from the spool gives the same holds.
#[derive(Debug, Clone, Default)]
pub struct Holds(HashMap<Destination, Hold>);

impl Holds {
	/// Add what `envelope` says: each pending recipient deferred by a
	/// slow-down reply holds its domain, and the exchanger that sent it,
	/// until its own next attempt.
	pub fn add_envelope(&mut self, envelope: &Envelope) {
		for recipient in &envelope.recipients {
			let state = envelope.recipient_state(recipient);
			if state.status != RecipientStatus::Pending || state.throttled == 0 {
				continue;
			}
			let reason = state.last_error.clone().unwrap_or_default();
			self.note(
				Destination::of_recipient(recipient),
				state.next_attempt,
				state.throttled,
				&reason,
			);
			if let Some(host) = &state.remote {
				self.note(
					Destination::exchanger(host),
					state.next_attempt,
					state.throttled,
					&reason,
				);
			}
		}
	}

	/// Count `destination` as held until `until` after `deferrals` in a
	/// row, keeping the longest wait and the most deferrals seen.
	pub fn note(&mut self, destination: Destination, until: u64, deferrals: u32, reason: &str) {
		let hold = self.0.entry(destination).or_insert_with(|| Hold {
			until,
			deferrals,
			reason: reason.to_string(),
		});
		if until > hold.until {
			hold.until = until;
			hold.reason = reason.to_string();
		}
		hold.deferrals = hold.deferrals.max(deferrals);
	}

	/// Every hold the spool shows. An entry that cannot be read is left
	/// out, as the worker leaves it out of its scan.
	pub fn read(spool: &crate::storage::FsSpool) -> std::io::Result<Self> {
		let mut holds = Holds::default();
		for id in spool.list()? {
			if let Ok(envelope) = spool.load_envelope(id) {
				holds.add_envelope(&envelope);
			}
		}
		Ok(holds)
	}

	/// The hold of `destination` when it is in force at `now`.
	pub fn held(&self, destination: &Destination, now: u64) -> Option<&Hold> {
		self.0.get(destination).filter(|hold| hold.until > now)
	}

	/// The slow-down deferrals in a row `destination` has behind it, in
	/// force or not.
	pub fn deferrals(&self, destination: &Destination) -> u32 {
		self.0.get(destination).map_or(0, |hold| hold.deferrals)
	}

	/// The holds in force at `now`, by destination.
	pub fn in_force(&self, now: u64) -> Vec<(&Destination, &Hold)> {
		let mut held: Vec<_> = self.0.iter().filter(|(_, hold)| hold.until > now).collect();
		held.sort_by(|a, b| a.0.cmp(b.0));
		held
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rate_limit_replies_hold_the_destination() {
		for reason in [
			"421 4.7.0 Try again later, closing connection",
			"421 mx.example.com service not available",
			"450 4.7.1 Client host rejected: too many connections",
			"451 4.7.650 The mail server has been temporarily rate limited",
			"451 Too many messages, slow down",
			"452 4.3.1 Rate limit exceeded",
		] {
			assert!(throttled(reason), "{reason}");
		}
	}

	#[test]
	fn other_deferrals_do_not_hold_the_destination() {
		for reason in [
			"452 4.5.3 too many recipients",
			"452 too many recipients",
			"452 4.2.2 mailbox full",
			"451 4.3.0 try again later",
			"450 4.2.0 mailbox busy",
			"timed out after 300s waiting for the greeting",
			"connection refused",
		] {
			assert!(!throttled(reason), "{reason}");
		}
	}

	#[test]
	fn too_many_recipients_is_its_own_case() {
		assert!(too_many_recipients("452 4.5.3 too many recipients"));
		assert!(too_many_recipients("452 Too many recipients"));
		assert!(!too_many_recipients("452 4.2.2 mailbox full"));
		assert!(!too_many_recipients("451 4.5.3 too many recipients"));
	}

	#[test]
	fn the_steps_grow_and_stay_at_the_last() {
		let steps = [60, 300, 900];
		assert_eq!(
			(0..5).map(|level| step(&steps, level)).collect::<Vec<_>>(),
			[60, 300, 900, 900, 900]
		);
		assert_eq!(step(&[], 0), DEFAULT_STEPS[0]);
	}
}

#[cfg(test)]
#[path = "backoff_tests_holds.rs"]
mod tests_holds;
