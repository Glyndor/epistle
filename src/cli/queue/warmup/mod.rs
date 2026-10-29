//! What `epistle queue` shows of the IP warm-up: the recipients waiting
//! for the daily cap of their receiver group. They are not deferred and
//! not held; they go out as the cap allows (see `epistle warmup status`).

use std::collections::BTreeMap;
use std::io::Write;

use crate::cli::term::sanitize;
use crate::storage::{Envelope, FsSpool, RecipientStatus};

/// Recipients waiting for one group's cap: how many, and the earliest
/// time one of them may be tried (epoch seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Waiting {
	pub(super) recipients: u64,
	pub(super) until: u64,
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
pub(super) fn waits(envelope: &Envelope) -> bool {
	groups(envelope).next().is_some()
}

/// Whether every pending recipient of `envelope` waits for a cap.
pub(super) fn only_waits(envelope: &Envelope) -> bool {
	let pending = envelope.pending();
	!pending.is_empty() && groups(envelope).count() == pending.len()
}

/// The recipients waiting for each group's cap, by group.
pub(super) fn waiting(spool: &FsSpool) -> std::io::Result<BTreeMap<String, Waiting>> {
	let mut by_group: BTreeMap<String, Waiting> = BTreeMap::new();
	for id in spool.list()? {
		let Ok(envelope) = spool.load_envelope(id) else {
			continue;
		};
		for (group, until) in groups(&envelope) {
			let entry = by_group.entry(group).or_insert(Waiting {
				recipients: 0,
				until,
			});
			entry.recipients += 1;
			entry.until = entry.until.min(until);
		}
	}
	Ok(by_group)
}

/// `queue destinations` lines for the groups at their cap.
pub(super) fn lines(waiting: &BTreeMap<String, Waiting>, now: u64, out: &mut impl Write) {
	for (group, wait) in waiting {
		let _ = writeln!(
			out,
			"warm-up {}\tuntil={} (in {}s)\twaiting={}\treason=warm-up cap",
			sanitize(group),
			crate::clock::rfc3339_or_epoch(wait.until),
			wait.until.saturating_sub(now),
			wait.recipients
		);
	}
}

/// `queue destinations --json` rows for the groups at their cap.
pub(super) fn json_rows(waiting: &BTreeMap<String, Waiting>) -> Vec<serde_json::Value> {
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

/// The line `queue list` adds when recipients wait for a cap.
pub(super) fn summary(spool: &FsSpool) -> Option<String> {
	let waiting = waiting(spool).ok()?;
	if waiting.is_empty() {
		return None;
	}
	let total: u64 = waiting.values().map(|wait| wait.recipients).sum();
	let groups: Vec<String> = waiting
		.iter()
		.map(|(group, wait)| format!("{} {}", sanitize(group), wait.recipients))
		.collect();
	Some(format!(
		"{total} recipients waiting for the warm-up cap: {} (see `epistle warmup status`)",
		groups.join(", ")
	))
}

#[cfg(test)]
mod tests;
