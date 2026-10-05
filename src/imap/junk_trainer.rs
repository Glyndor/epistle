//! What a `$Junk` / `$NotJunk` keyword change teaches the account corpus.
//!
//! IMAP STORE and JMAP `Email/set` both call [`enqueue_junk_transition`]
//! with the flag sets before and after the change, so the two protocols
//! cannot disagree on what a mark means.

use std::path::PathBuf;

use crate::antispam::training_queue::{TrainingJob, TrainingQueue};
use crate::imap::mailbox::Flag;

/// The side of the corpus a keyword change trains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JunkSignal {
	/// The user said the message is junk.
	Spam,
	/// The user said the message is not junk.
	Ham,
}

/// Decide what the change from `previous` to `updated` teaches.
///
/// | change                                   | result |
/// |------------------------------------------|--------|
/// | `$Junk` added                            | spam   |
/// | `$NotJunk` added                         | ham    |
/// | `$Junk` removed, `$NotJunk` not added    | ham    |
/// | `$NotJunk` removed and nothing else       | none   |
/// | both added in the same change            | none   |
/// | neither keyword changed                  | none   |
///
/// Removing `$Junk` says the message was not junk. Removing `$NotJunk`
/// only retracts an earlier ham mark, which says nothing about the
/// message being spam, so it trains nothing. Adding both at once is
/// contradictory and trains nothing. Keywords match without regard to
/// case (RFC 9051 section 2.3.2), so `$junk` replacing `$Junk` is no
/// change.
pub fn junk_signal(previous: &[Flag], updated: &[Flag]) -> Option<JunkSignal> {
	let had_junk = previous.iter().any(Flag::is_junk);
	let has_junk = updated.iter().any(Flag::is_junk);
	let had_not_junk = previous.iter().any(Flag::is_not_junk);
	let has_not_junk = updated.iter().any(Flag::is_not_junk);
	let added_junk = has_junk && !had_junk;
	let added_not_junk = has_not_junk && !had_not_junk;
	let removed_junk = had_junk && !has_junk;
	match (added_junk, added_not_junk, removed_junk) {
		(true, true, _) => None,
		(true, false, _) => Some(JunkSignal::Spam),
		(false, true, _) | (false, false, true) => Some(JunkSignal::Ham),
		(false, false, false) => None,
	}
}

/// Queue a training job when the change from `previous` to `updated`
/// carries a [`JunkSignal`]. Returns whether a job was queued. Never
/// waits and never fails: a full queue drops the job (see
/// [`TrainingQueue::submit`]). `path` is the stored message file.
pub fn enqueue_junk_transition(
	queue: &TrainingQueue,
	account: &str,
	previous: &[Flag],
	updated: &[Flag],
	path: PathBuf,
) -> bool {
	let Some(signal) = junk_signal(previous, updated) else {
		return false;
	};
	queue.submit(TrainingJob {
		account: account.to_string(),
		path,
		spam: signal == JunkSignal::Spam,
	})
}

#[cfg(test)]
#[path = "junk_trainer_tests.rs"]
mod tests;
