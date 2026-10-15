//! How each receiver group took our mail on one day, read from the
//! delivery log.
//!
//! Every record that a remote server answered is put in the group of that
//! server (see [`Group::of_exchanger`]) and counted by what its reply code
//! says, never by its text: a remote writes whatever it likes after the
//! code, so the words in a reply cannot make a deferral look like a block.
//!
//! - A recipient is *attempted* once a day, however many records it has.
//! - It is *deferred* when a deferral asked us to slow down for reputation
//!   or rate: a `421`, or any `4.7.x`. A greylist or a full mailbox is not
//!   counted. A recipient counts once a day here too, so a remote that words
//!   every retry differently gains nothing.
//! - A *bounce* is a permanent refusal (`5xx`) other than a policy one,
//!   unknown users included: receivers count mail to dead addresses
//!   against the sender, so a list with many of them must not grow.
//! - A *spam block* is a permanent `5.7.x` policy refusal.
//!
//! Records with no remote answer (a local error, a suppression, a cancel,
//! an expiry with no reply) say nothing about the receiver and are left out.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

use super::Group;
use crate::queue::reply::parse_enhanced;
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

/// The most recipients one day's tally tells apart. Past it, a recipient
/// seen again is counted again rather than remembered, so a day of any
/// size is read in bounded memory.
pub const MAX_RECIPIENTS: usize = 200_000;

/// What one group's records of one day add up to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
	/// Recipients a remote server of the group answered for.
	pub attempted: u32,
	/// Recipients deferred by a rate or reputation reply.
	pub deferred: u32,
	/// Permanent refusals other than policy ones.
	pub bounced: u32,
	/// Permanent `5.7.x` refusals.
	pub spam_blocks: u32,
}

/// What a record says about the group that answered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
	/// The remote took the message.
	Delivered,
	/// A rate or reputation deferral.
	Throttled,
	/// Any other deferral.
	Deferred,
	/// A permanent refusal that is not about policy.
	Bounced,
	/// A permanent `5.7.x` refusal.
	SpamBlock,
}

/// The reply code and the subject and detail of the enhanced status at
/// the head of a stored reply (`421 4.7.0 ...`), read like the queue reads
/// it: the enhanced status counts only when its class agrees with the code.
fn codes(reply: &str) -> Option<(u16, Option<(u16, u16)>)> {
	let head = reply.get(..3)?;
	if !head.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	let rest = reply.get(3..).unwrap_or_default();
	if !(rest.is_empty() || rest.starts_with([' ', '-'])) {
		return None;
	}
	let code: u16 = head.parse().ok()?;
	let enhanced = rest
		.get(1..)
		.unwrap_or_default()
		.split_whitespace()
		.next()
		.and_then(parse_enhanced)
		.filter(|enhanced| enhanced.class == code / 100)
		.map(|enhanced| (enhanced.subject, enhanced.detail));
	Some((code, enhanced))
}

/// What `record` says, or `None` when no remote answered it.
pub fn signal(record: &DeliveryRecord) -> Option<Signal> {
	record.remote.as_ref()?;
	match record.outcome {
		DeliveryOutcome::Delivered => Some(Signal::Delivered),
		DeliveryOutcome::Deferred => match codes(record.reply.as_deref()?)? {
			(421, _) => Some(Signal::Throttled),
			(400..=499, Some((7, _))) => Some(Signal::Throttled),
			(400..=499, _) => Some(Signal::Deferred),
			_ => None,
		},
		DeliveryOutcome::Failed => match codes(record.reply.as_deref()?)? {
			(500..=599, Some((7, _))) => Some(Signal::SpamBlock),
			(500..=599, _) => Some(Signal::Bounced),
			_ => None,
		},
		DeliveryOutcome::Suppressed | DeliveryOutcome::Canceled => None,
	}
}

/// What has been counted of one recipient so far today.
#[derive(Default, Clone, Copy)]
struct Seen {
	deferred: bool,
}

/// One day of records, tallied by group.
#[derive(Default)]
pub struct DayTally {
	groups: BTreeMap<Group, Tally>,
	seen: HashMap<u64, Seen>,
}

impl DayTally {
	/// Count `record`.
	pub fn add(&mut self, record: &DeliveryRecord) {
		let Some(signal) = signal(record) else {
			return;
		};
		let group = Group::of_exchanger(record.remote.as_deref().unwrap_or_default());
		let key = recipient_key(record);
		let full = self.seen.len() >= MAX_RECIPIENTS;
		let (first, before) = match self.seen.get(&key) {
			Some(seen) => (false, *seen),
			None => (true, Seen::default()),
		};
		let tally = self.groups.entry(group).or_default();
		if first {
			tally.attempted = tally.attempted.saturating_add(1);
		}
		let mut after = before;
		match signal {
			Signal::Throttled if !before.deferred => {
				tally.deferred = tally.deferred.saturating_add(1);
				after.deferred = true;
			}
			Signal::Bounced => tally.bounced = tally.bounced.saturating_add(1),
			Signal::SpamBlock => tally.spam_blocks = tally.spam_blocks.saturating_add(1),
			_ => {}
		}
		if !full || !first {
			self.seen.insert(key, after);
		}
	}

	/// The tally of `group`, zero when it had no records.
	pub fn of(&self, group: Group) -> Tally {
		self.groups.get(&group).copied().unwrap_or_default()
	}

	/// How many recipients are told apart.
	pub fn remembered(&self) -> usize {
		self.seen.len()
	}
}

/// The key one recipient of one message is told apart by.
fn recipient_key(record: &DeliveryRecord) -> u64 {
	let mut hasher = std::collections::hash_map::DefaultHasher::new();
	record.spool_id.hash(&mut hasher);
	record.recipient.hash(&mut hasher);
	hasher.finish()
}

/// Tally the UTC day `unix_day` of `log`.
pub fn tally_day(log: &DeliveryLog, unix_day: i64) -> std::io::Result<DayTally> {
	let mut tally = DayTally::default();
	log.for_each_on_day(unix_day, |record| tally.add(record))?;
	Ok(tally)
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
