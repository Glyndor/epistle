//! What moving a message into or out of Junk teaches the account corpus.
//!
//! IMAP COPY and MOVE and JMAP `Email/set` reach the same decision here, so
//! the two protocols cannot disagree on what a move means. The decision is
//! taken from the names of the two mailboxes as the server resolved them,
//! and the message is named by the file the server wrote, never by anything
//! the client sent.

use std::path::Path;

use uuid::Uuid;

use super::junk_trainer::JunkSignal;
use super::special_use::{is_junk, is_trash};
use crate::antispam::training_queue::{LessonBudget, TrainingJob, TrainingQueue};
use crate::util::path_component::{MessageExt, message_file};

/// What a message that goes from `source` to `target` teaches.
///
/// | move                                           | result |
/// |------------------------------------------------|--------|
/// | into Junk, copy or move                        | spam   |
/// | out of Junk by a move to a mailbox but Trash   | ham    |
/// | out of Junk by a copy                          | none   |
/// | out of Junk to Trash                           | none   |
/// | between two mailboxes that are both, or neither, Junk | none |
///
/// A copy out of Junk leaves the message in Junk, so it says nothing about
/// the message not being junk. Junk to Trash is the user throwing spam away,
/// not vouching for it.
pub fn move_signal(source: &str, target: &str, removes_source: bool) -> Option<JunkSignal> {
	match (is_junk(source), is_junk(target)) {
		(false, true) => Some(JunkSignal::Spam),
		(true, false) if removes_source && !is_trash(target) => Some(JunkSignal::Ham),
		_ => None,
	}
}

/// Queue the lessons for the messages a command stored in the mailbox whose
/// directory is `dir`, under the ids `stored`, and return how many were
/// queued. The command's `budget` caps how many are looked at, whatever the
/// protocol and however many messages the command touched; the rest are
/// counted as dropped, so a move of thousands of messages costs a bounded
/// amount and never waits for the worker.
pub fn enqueue_move(
	queue: &TrainingQueue,
	account: &str,
	signal: JunkSignal,
	dir: &Path,
	stored: &[Uuid],
	budget: &mut LessonBudget,
) -> usize {
	let granted = budget.take(stored.len());
	queue.note_dropped(stored.len() - granted);
	let mut queued = 0;
	for id in &stored[..granted] {
		let Ok(path) = message_file(dir, *id, MessageExt::Eml) else {
			continue;
		};
		let job = TrainingJob {
			account: account.to_string(),
			path,
			spam: signal == JunkSignal::Spam,
		};
		if queue.submit(job) {
			queued += 1;
		}
	}
	queued
}

#[cfg(test)]
mod tests;
