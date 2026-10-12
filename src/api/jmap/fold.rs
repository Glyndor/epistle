//! Fold journal entries into the per-id outcome a `/changes` or
//! `/queryChanges` reply reports.
//!
//! An id can change several times after the client's state. What matters is
//! whether it existed at the old state (its first change there is not a
//! create) and whether it exists now (its last change is not a destroy):
//! created then destroyed is not reported at all, destroyed then created
//! again (a mailbox name reused) is an update.

use crate::imap::changelog::{Entry, Object, Op};

/// What happened to one id between the old state and the fold's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
	Created,
	/// `only_updates` is true when every change was an in-place update (for a
	/// mailbox: only its counts moved).
	Updated {
		only_updates: bool,
	},
	Destroyed,
}

/// The folded changes, in the order each id first changed.
#[derive(Debug, Default)]
pub(crate) struct Folded {
	pub outcomes: Vec<(String, Outcome)>,
	/// Position the reply covers: the journal end, or the position just
	/// before the first entry left for the next page.
	pub through: u64,
	pub has_more: bool,
}

impl Folded {
	pub(crate) fn ids(&self, wanted: impl Fn(Outcome) -> bool) -> Vec<String> {
		self.outcomes
			.iter()
			.filter(|(_, outcome)| wanted(*outcome))
			.map(|(id, _)| id.clone())
			.collect()
	}
}

struct Track {
	first: Op,
	last: Op,
	only_updates: bool,
}

/// Fold the `object` entries of `entries` (sorted by position, all after the
/// old state). With `max`, stop before the entry that would make more than
/// `max` distinct ids, so the reply ends on a position the client can resume
/// from. `skip_updates` drops in-place updates first (a Thread does not change
/// when its email's keywords do).
pub(crate) fn fold(
	entries: &[Entry],
	object: Object,
	max: Option<usize>,
	skip_updates: bool,
	end: u64,
) -> Folded {
	let mut order: Vec<String> = Vec::new();
	let mut tracks: std::collections::HashMap<String, Track> = std::collections::HashMap::new();
	let mut folded = Folded {
		through: end,
		..Folded::default()
	};
	for entry in entries {
		let change = &entry.change;
		if change.object != object || (skip_updates && change.op == Op::Updated) {
			continue;
		}
		if let Some(track) = tracks.get_mut(&change.id) {
			track.last = change.op;
			track.only_updates &= change.op == Op::Updated;
			continue;
		}
		if max.is_some_and(|max| order.len() >= max) {
			folded.through = entry.position - 1;
			folded.has_more = true;
			break;
		}
		order.push(change.id.clone());
		tracks.insert(
			change.id.clone(),
			Track {
				first: change.op,
				last: change.op,
				only_updates: change.op == Op::Updated,
			},
		);
	}
	for id in order {
		let Some(track) = tracks.remove(&id) else {
			continue;
		};
		let existed = track.first != Op::Created;
		let exists = track.last != Op::Destroyed;
		let outcome = match (existed, exists) {
			(true, true) => Outcome::Updated {
				only_updates: track.only_updates,
			},
			(true, false) => Outcome::Destroyed,
			(false, true) => Outcome::Created,
			(false, false) => continue,
		};
		folded.outcomes.push((id, outcome));
	}
	folded
}

#[cfg(test)]
#[path = "fold_tests.rs"]
mod tests;
