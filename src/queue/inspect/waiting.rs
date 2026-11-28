//! The recipients waiting for the daily cap of their receiver group, which
//! `epistle queue` and the queue routes both show. They are not deferred and
//! not held; they go out as the cap allows.

use std::collections::BTreeMap;

use crate::storage::{Envelope, FsSpool, RecipientStatus};

/// Recipients waiting for one group's cap: how many, and the earliest
/// time one of them may be tried (epoch seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waiting {
	/// How many recipients wait.
	pub recipients: u64,
	/// The earliest time one of them may be tried, in epoch seconds.
	pub until: u64,
}

/// The groups of `envelope`'s pending recipients that wait for a cap.
fn groups(envelope: &Envelope) -> impl Iterator<Item = (String, u64)> + '_ {
	envelope.recipients.iter().filter_map(|recipient| {
		let state = envelope.recipient_state(recipient);
		match (state.status, state.warmup) {
			(RecipientStatus::Pending, Some(group)) => Some((group, state.next_attempt)),
			_ => None,
		}
	})
}

/// Whether a pending recipient of `envelope` waits for a cap.
pub fn waits(envelope: &Envelope) -> bool {
	groups(envelope).next().is_some()
}

/// Whether every pending recipient of `envelope` waits for a cap.
pub fn only_waits(envelope: &Envelope) -> bool {
	let pending = envelope.pending();
	!pending.is_empty() && groups(envelope).count() == pending.len()
}

/// The recipients waiting for each group's cap, by group.
pub fn waiting(spool: &FsSpool) -> std::io::Result<BTreeMap<String, Waiting>> {
	let mut by_group: BTreeMap<String, Waiting> = BTreeMap::new();
	for id in spool.list()? {
		let Ok(envelope) = spool.load_envelope(id) else {
			continue;
		};
		count(&mut by_group, &envelope);
	}
	Ok(by_group)
}

/// Add the recipients of `envelope` that wait for a cap to `by_group`.
pub(super) fn count(by_group: &mut BTreeMap<String, Waiting>, envelope: &Envelope) {
	for (group, until) in groups(envelope) {
		let entry = by_group.entry(group).or_insert(Waiting {
			recipients: 0,
			until,
		});
		entry.recipients += 1;
		entry.until = entry.until.min(until);
	}
}

/// `queue destinations --json` rows for the groups at their cap.
pub fn json_rows(waiting: &BTreeMap<String, Waiting>) -> Vec<serde_json::Value> {
	waiting
		.iter()
		.map(|(group, wait)| {
			serde_json::json!({
				"kind": "warmup",
				"name": group,
				"until": wait.until,
				"waiting": wait.recipients,
				"reason": "warm-up cap",
			})
		})
		.collect()
}
