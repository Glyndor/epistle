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
//!
//! Reputation belongs to the sending address, so every account's mail is
//! judged together: one account mailing dead addresses or spam traps can
//! hold or step back a group's cap for everyone. That cannot be prevented
//! without letting the bad mail itself go on, so it is made visible: each
//! bad reply is put to the account that submitted the message (`system`
//! for mail the server sends on its own), and a judged day names the
//! accounts with the most ([`DayTally::causes`]) so the operator can slow
//! or stop that account.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

use super::Group;
use crate::queue::reply::parse_enhanced;
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

/// The most recipients one day's tally tells apart. Past it, a recipient
/// seen again is counted again rather than remembered, so a day of any
/// size is read in bounded memory.
pub const MAX_RECIPIENTS: usize = 200_000;

/// The most accounts one group's day tells apart; past it the rest are
/// counted together under [`super::state::OVERFLOW_SENDER`].
pub const MAX_ACCOUNTS: usize = 1024;
/// How many accounts a judged day names.
pub const NAMED_CAUSES: usize = 3;

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
	/// Bad replies per account, by group.
	causes: BTreeMap<Group, HashMap<String, u32>>,
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
		let bad = match signal {
			Signal::Throttled if !before.deferred => {
				tally.deferred = tally.deferred.saturating_add(1);
				after.deferred = true;
				true
			}
			Signal::Bounced => {
				tally.bounced = tally.bounced.saturating_add(1);
				true
			}
			Signal::SpamBlock => {
				tally.spam_blocks = tally.spam_blocks.saturating_add(1);
				true
			}
			_ => false,
		};
		if bad {
			self.blame(group, record.account.as_deref());
		}
		if !full || !first {
			self.seen.insert(key, after);
		}
	}

	/// The tally of `group`, zero when it had no records.
	pub fn of(&self, group: Group) -> Tally {
		self.groups.get(&group).copied().unwrap_or_default()
	}

	/// The accounts with the most bad replies in `group`, most first, at
	/// most [`NAMED_CAUSES`] of them.
	pub fn causes(&self, group: Group) -> Vec<super::state::Cause> {
		let Some(accounts) = self.causes.get(&group) else {
			return Vec::new();
		};
		let mut causes: Vec<(&String, &u32)> = accounts.iter().collect();
		causes.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
		causes
			.into_iter()
			.take(NAMED_CAUSES)
			.map(|(account, bad)| super::state::Cause {
				account: account.clone(),
				bad: *bad,
			})
			.collect()
	}

	/// Count one bad reply against the account that submitted the message,
	/// or `system` for mail with none.
	fn blame(&mut self, group: Group, account: Option<&str>) {
		let accounts = self.causes.entry(group).or_default();
		let account = account
			.filter(|account| !account.is_empty())
			.unwrap_or("system");
		let key = match accounts.contains_key(account) || accounts.len() < MAX_ACCOUNTS {
			true => account,
			false => super::state::OVERFLOW_SENDER,
		};
		*accounts.entry(key.to_string()).or_default() += 1;
	}

	/// How many accounts `group`'s day tells apart.
	pub fn accounts(&self, group: Group) -> usize {
		self.causes.get(&group).map_or(0, HashMap::len)
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
