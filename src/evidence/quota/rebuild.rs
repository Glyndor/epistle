//! Rebuilding the book from the records of the day in the chain.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use uuid::Uuid;

use super::book::{Book, Owed};
use super::limits::Limits;
use super::state::State;
use super::{Quota, UNATTRIBUTED};
use crate::evidence::chain::{CHAIN_DIR, day_file, open_day};
use crate::evidence::day::Day;
use crate::evidence::lines::{Line, Lines};
use crate::evidence::record::{Entry, MAX_RECORDS_PER_DAY, Record, RetentionMode};

/// The most messages of the last days whose account is remembered at start.
const MAX_NAMED: usize = 1_000_000;

impl Quota {
	/// The quota for the log under `evidence_root`. Its book is rebuilt from
	/// the records of the day on first use, so that starting it reads no clock.
	/// A log that cannot be read leaves the book unavailable: no acceptance
	/// until it can be.
	pub fn start(evidence_root: &Path, limits: Limits) -> Quota {
		Quota {
			root: evidence_root.to_path_buf(),
			limits: limits.fitted(),
			book: Mutex::new(Book {
				state: State::default(),
				loaded: false,
				unavailable: None,
				tried: None,
			}),
		}
	}

	/// [`start`](Self::start), rebuilt for `today` at once.
	#[cfg(test)]
	pub(crate) fn start_at(evidence_root: &Path, limits: Limits, today: Day) -> Quota {
		let quota = Self::start(evidence_root, limits);
		quota.ensure(&mut quota.book(), today);
		quota
	}

	/// Rebuild the book the first time it is used.
	pub(super) fn ensure(&self, book: &mut Book, today: Day) {
		if !book.loaded {
			book.loaded = true;
			self.rebuild(book, today);
		}
	}

	/// Rebuild `book` from today's day file.
	pub(super) fn rebuild(&self, book: &mut Book, today: Day) {
		book.tried = Some(Instant::now());
		match self.read_day(today) {
			Ok(state) => {
				if book.unavailable.take().is_some() {
					tracing::warn!("the evidence quota was rebuilt from the log");
				}
				// What is remembered of earlier days' outcomes stays.
				let kept = std::mem::take(&mut book.state.owed);
				book.state = state;
				for (id, owed) in kept {
					if !book.state.owed.contains_key(&id) && book.state.has_room_for(&owed.account)
					{
						book.state.track(id, owed);
					}
				}
			}
			Err(error) => {
				if book.unavailable.is_none() {
					tracing::error!(%error, "the evidence quota cannot be rebuilt from the log: no new acceptances until it can");
				}
				book.unavailable = Some(error.to_string());
			}
		}
	}

	/// Which account each message of the last days was accepted for, from the
	/// day files before `today`. Bounded: past [`MAX_NAMED`] it learns no more.
	fn accepted_before(&self, today: Day, names: &mut HashMap<Uuid, String>) {
		for back in [2, 1] {
			let Ok(file) = open_day(&day_file(&self.root.join(CHAIN_DIR), Day(today.0 - back)))
			else {
				continue;
			};
			let mut lines = Lines::new(std::io::BufReader::new(file));
			while let Ok(Some((_, line))) = lines.next_line() {
				if let Line::Complete(bytes) = line
					&& let Ok(Entry::Accepted(accepted)) =
						Record::parse_canonical(bytes).map(|record| record.entry)
					&& names.len() < MAX_NAMED
				{
					names.insert(accepted.spool_id, accepted.account);
				}
			}
		}
	}

	/// The counts of the records of `today` in the chain.
	fn read_day(&self, today: Day) -> std::io::Result<State> {
		let share = (self.limits.account_records, self.limits.day_records);
		let mut state = State {
			day: today.0,
			..State::default()
		};
		let mut names: HashMap<Uuid, String> = HashMap::new();
		self.accepted_before(today, &mut names);
		let file = match open_day(&day_file(&self.root.join(CHAIN_DIR), today)) {
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(state),
			Err(error) => return Err(error),
		};
		let mut lines = Lines::new(std::io::BufReader::new(file));
		let mut read = 0u64;
		while let Some((_, line)) = lines.next_line()? {
			read += 1;
			if read > MAX_RECORDS_PER_DAY {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"more records in a day than any day may hold",
				));
			}
			let Line::Complete(bytes) = line else {
				state.add(UNATTRIBUTED, 1, 0, share);
				continue;
			};
			match Record::parse_canonical(bytes).map(|record| record.entry) {
				Ok(Entry::Accepted(accepted)) => {
					let recipients = accepted.recipients.len() as u64;
					let kept = match accepted.retention.mode {
						RetentionMode::Full => accepted.size,
						_ => 0,
					};
					// History is not refused: an acceptance the memory has no room
					// for is counted for its own record, and its outcomes when
					// they are met, once.
					let paid = recipients > 0 && state.has_room_for(&accepted.account);
					state.add(
						&accepted.account,
						1 + if paid { recipients } else { 0 },
						kept,
						share,
					);
					if paid {
						state.track(
							accepted.spool_id,
							Owed {
								left: recipients,
								day: today.0,
								account: accepted.account.clone(),
							},
						);
					}
					if names.len() < MAX_NAMED {
						names.insert(accepted.spool_id, accepted.account);
					}
				}
				Ok(Entry::Outcome(crate::evidence::record::Outcome { spool_id, .. })) => {
					let account = names.get(&spool_id).map(String::as_str);
					Self::settle(&mut state, account, (spool_id, false), share);
				}
				Ok(Entry::Abandoned(crate::evidence::record::Abandoned { spool_id, .. })) => {
					let account = names.get(&spool_id).map(String::as_str);
					Self::settle(&mut state, account, (spool_id, true), share);
				}
				_ => {
					state.add(UNATTRIBUTED, 1, 0, share);
				}
			}
		}
		Ok(state)
	}

	/// Count a fact: not at all if its acceptance paid for it, else once. A
	/// fact that `ends` the message (an abandonment, which stands for all its
	/// outcomes) also forgets what was still owed for it.
	pub(super) fn settle(
		state: &mut State,
		account: Option<&str>,
		(id, ends): (Uuid, bool),
		share: (u64, u64),
	) {
		let prepaid = state.owed.get(&id).is_some_and(|owed| owed.left > 0);
		if prepaid {
			if let Some(owed) = state.owed.get_mut(&id) {
				owed.left -= 1;
			}
			if ends || state.owed.get(&id).is_some_and(|owed| owed.left == 0) {
				state.untrack(id);
			}
			return;
		}
		if ends {
			state.untrack(id);
		}
		state.add(account.unwrap_or(UNATTRIBUTED), 1, 0, share);
	}
}
