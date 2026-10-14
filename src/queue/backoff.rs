//! Backing off a destination that asks the queue to slow down.
//!
//! Large receivers answer a sender that goes too fast with a 421 (often at
//! the greeting), a 4.7.x status, or a 451 or 452 that says the sender hit a
//! rate limit. Retrying each message on its own schedule would keep hitting
//! them; instead the whole recipient domain is put on hold, and every
//! message to it waits. The hold grows with each deferral in a row, through
//! the configured steps (1, 5, 15 and 60 minutes by default), and a
//! conversation that delivers ends it.
//!
//! A `452 4.5.3` (too many recipients) is different: the remote took some
//! recipients and asks for the rest in another transaction. Those are not
//! failures and are retried at once, not held off.

use crate::queue::reply::parse_enhanced;
use crate::storage::{DestinationHold, DestinationHolds};

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

/// The hold of a destination that deferred for `reason` at `now`, given
/// the hold it had (if any). A hold still running is kept as it is: two
/// conversations deferred by the same burst count as one deferral. One
/// that ran out moves to the next step.
pub fn next_hold(
	steps: &[u64],
	previous: Option<&DestinationHold>,
	reason: &str,
	now: u64,
) -> DestinationHold {
	if let Some(previous) = previous.filter(|hold| hold.active(now)) {
		return previous.clone();
	}
	let level = previous.map_or(0, |hold| hold.level.saturating_add(1));
	let step = steps
		.get(level as usize)
		.or(steps.last())
		.copied()
		.unwrap_or(DEFAULT_STEPS[0]);
	DestinationHold {
		until: now.saturating_add(step),
		level,
		reason: reason.chars().take(200).collect(),
		since: previous.map_or(now, |hold| hold.since),
	}
}

/// Whether `domain` is on hold at `now`.
pub fn is_held(holds: &DestinationHolds, domain: &str, now: u64) -> bool {
	holds.get(domain).is_some_and(|hold| hold.active(now))
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
	fn holds_grow_through_the_steps_and_stay_at_the_last() {
		let steps = [60, 300, 900];
		let first = next_hold(&steps, None, "421 busy", 1000);
		assert_eq!((first.until, first.level, first.since), (1060, 0, 1000));
		// A deferral while the hold runs keeps it.
		assert_eq!(next_hold(&steps, Some(&first), "421 again", 1030), first);
		let second = next_hold(&steps, Some(&first), "421 again", 1060);
		assert_eq!((second.until, second.level, second.since), (1360, 1, 1000));
		let third = next_hold(&steps, Some(&second), "421 again", 1400);
		assert_eq!((third.until, third.level), (2300, 2));
		let fourth = next_hold(&steps, Some(&third), "421 again", 2300);
		assert_eq!((fourth.until, fourth.level), (3200, 3));
	}
}
