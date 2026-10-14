//! Backing off a destination that asks the queue to slow down.
//!
//! Large receivers answer a sender that goes too fast with a 421 (often at
//! the greeting), a 4.7.x status, or a 451 or 452 that says the sender hit a
//! rate limit. Retrying each message on its own schedule would keep hitting
//! them; instead the whole recipient domain is put on hold, and so is the
//! exchanger host that answered ([`exchanger_key`]): a provider that hosts
//! many domains limits the sender on its own hosts, so no other domain it
//! serves gets a fresh conversation with that host either. Every message to
//! a held destination waits. The hold grows with each deferral in a row,
//! through the configured steps (1, 5, 15 and 60 minutes by default), also
//! when a hold ran out without a delivery in between, and only a
//! conversation that delivers after the hold has run out ends it.
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
		sender: previous.and_then(|hold| hold.sender.clone()),
	}
}

/// The most destinations kept on hold at once. Anyone who can make the
/// server send to many domains that all defer could otherwise grow the
/// holds file, read on every scheduling decision, without bound.
pub const MAX_HOLDS: usize = 1024;

/// The key under which an exchanger host is held, next to the recipient
/// domains: many domains hosted by one provider share its exchangers, and
/// the provider's rate limit is on its own hosts, not on each domain.
pub fn exchanger_key(host: &str) -> String {
	format!("mx:{}", host.trim_end_matches('.').to_ascii_lowercase())
}

/// The most holds one sender's conversations may have created, a quarter
/// of [`MAX_HOLDS`]: one account sending to many deferring domains fills
/// its own quota, not the room every other sender's holds need.
pub const MAX_HOLDS_PER_SENDER: usize = MAX_HOLDS / 4;

/// How long a hold is remembered after it ran out with no delivery since:
/// a week. Until then a new deferral continues the run of steps; after a
/// week without a single deferral there is nothing left to slow down.
pub const HOLD_MEMORY_SECS: u64 = 7 * 86_400;

/// Record in `holds` that `key` (a recipient domain or an
/// [`exchanger_key`]) deferred a conversation of `sender` for `reason` at
/// `now`, and return its hold.
///
/// A hold is forgotten when its destination delivers again after it ran
/// out, when the operator releases it, or [`HOLD_MEMORY_SECS`] after it ran
/// out, so the backoff keeps growing through deferrals that come after a
/// hold ran out. No hold ever gives way to make room: past [`MAX_HOLDS`],
/// or past [`MAX_HOLDS_PER_SENDER`] created by `sender`, a destination not
/// yet held is not recorded (`None`) and its recipients follow their own
/// retry schedule, so flooding the queue with distinct deferring
/// destinations cannot free, or reset, the hold of another.
pub fn record_hold(
	holds: &mut DestinationHolds,
	steps: &[u64],
	(key, sender): (&str, &str),
	reason: &str,
	now: u64,
) -> Option<DestinationHold> {
	holds.retain(|_, hold| hold.active(now) || hold.until.saturating_add(HOLD_MEMORY_SECS) > now);
	if !holds.contains_key(key) {
		let by_sender = holds
			.values()
			.filter(|hold| hold.sender.as_deref() == Some(sender))
			.count();
		if holds.len() >= MAX_HOLDS || by_sender >= MAX_HOLDS_PER_SENDER {
			return None;
		}
	}
	let mut hold = next_hold(steps, holds.get(key), reason, now);
	hold.sender.get_or_insert_with(|| sender.to_string());
	holds.insert(key.to_string(), hold.clone());
	Some(hold)
}

/// Forget the hold of `key` after a delivery, unless it is still in
/// force: a destination that set a hold for all senders' conversations
/// keeps it until it ends, even when one that was already under way got
/// through. Returns whether a hold was removed.
pub fn clear_after_success(holds: &mut DestinationHolds, key: &str, now: u64) -> bool {
	match holds.get(key) {
		Some(hold) if !hold.active(now) => holds.remove(key).is_some(),
		_ => false,
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
	fn an_exchanger_is_held_under_its_own_key() {
		assert_eq!(
			exchanger_key("MX1.Provider.Example."),
			"mx:mx1.provider.example"
		);
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

#[cfg(test)]
#[path = "backoff_tests_holds.rs"]
mod tests_holds;
