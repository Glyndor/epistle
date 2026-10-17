//! A queued message taken out of the queue leaves a record.
//!
//! An acceptance whose message an operator removed would otherwise stay in
//! the log with no ending, as if the queue still held it, and nothing would
//! say who stopped it. Each recipient still waiting gets a `canceled` outcome
//! before the entry goes, so the message can be shown whole and what became
//! of it is on record.

use std::collections::HashSet;
use std::path::Path;

use super::chain::Chain;
use super::record::{Entry, Outcome, OutcomeKind};
use crate::storage::{Envelope, RecipientStatus};

/// How the writing fails in a test.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fail {
	/// The record is refused and not written.
	Clean,
	/// The record is written and the writer cannot say so.
	WrittenUnconfirmed,
	/// The record is not written and the writer cannot say so.
	UnwrittenUnconfirmed,
}

/// Make the writing fail at the record with this index, for tests.
#[cfg(test)]
thread_local! {
	pub(super) static FAIL_AT: std::cell::Cell<Option<(usize, Fail)>> = const { std::cell::Cell::new(None) };
}

/// What the outcome says happened to the message.
pub const REASON: &str = "removed from the queue before it was delivered";

/// Take entry `id` out of `spool`, leaving the record of it. The envelope is
/// read again under the spool's lock, the cancellation is recorded from that
/// one, and only then are the files unlinked, all as one step: a worker that
/// settled, delivered or marked an outcome owed in the meantime is seen, and an
/// entry that is owed an outcome, or whose record cannot be written, stays.
/// Returns the envelope as it was removed.
pub fn remove(
	spool: &crate::storage::FsSpool,
	evidence_root: &Path,
	id: uuid::Uuid,
) -> std::io::Result<Envelope> {
	spool.remove_with(id, |fresh, partial| {
		record_partly(evidence_root, fresh, partial).map(|_| ())
	})
}

/// Record a `canceled` outcome for every recipient of `envelope` still
/// waiting, when the entry keeps evidence. Returns how many were written.
/// The entry must not be removed unless this returned `Ok`.
pub fn record(evidence_root: &Path, envelope: &Envelope) -> std::io::Result<usize> {
	record_partly(evidence_root, envelope, &std::cell::Cell::new(false))
}

/// [`record`], raising `partial` before each write and lowering it only when
/// a failure says nothing was written, so that a failure after something may
/// have been written can be told from one before it. A recipient the chain
/// already shows as canceled since the entry was put on hold (an earlier try
/// that was cut short) is not written again.
fn record_partly(
	evidence_root: &Path,
	envelope: &Envelope,
	partial: &std::cell::Cell<bool>,
) -> std::io::Result<usize> {
	if !envelope.evidence {
		return Ok(0);
	}
	let chain = Chain::open(evidence_root)?;
	let done = match envelope.held {
		Some(since) => already(evidence_root, &chain, envelope.id, since)?,
		None => HashSet::new(),
	};
	let mut written = 0;
	for (index, recipient) in envelope.recipients.iter().enumerate() {
		let state = envelope.recipient_state(recipient);
		if state.status != RecipientStatus::Pending || done.contains(recipient.as_str()) {
			continue;
		}
		let before = partial.replace(true);
		let outcome = Entry::Outcome(Outcome {
			spool_id: envelope.id,
			class: envelope.class,
			recipient: super::record::bounded(recipient),
			result: OutcomeKind::Canceled,
			attempt: state.attempts,
			remote: state.remote.as_deref().map(super::record::bounded),
			reply: Some(REASON.to_string()),
			tls: None,
			dane: false,
			mta_sts: None,
			retain_days: match envelope.retain_days {
				0 => super::policy::DEFAULT_DAYS,
				days => days,
			},
		});
		#[cfg(test)]
		let appended = match FAIL_AT.with(std::cell::Cell::get) {
			Some((at, Fail::Clean)) if at == index => {
				Err(std::io::Error::other("injected: the record is refused"))
			}
			Some((at, Fail::UnwrittenUnconfirmed)) if at == index => Err(
				super::chain::Unconfirmed::wrap(std::io::Error::other("injected: not confirmed")),
			),
			Some((at, Fail::WrittenUnconfirmed)) if at == index => {
				chain.append(outcome)?;
				Err(super::chain::Unconfirmed::wrap(std::io::Error::other(
					"injected: written, not confirmed",
				)))
			}
			_ => chain.append(outcome).map(|_| ()),
		};
		#[cfg(not(test))]
		let appended = {
			let _ = index;
			chain.append(outcome).map(|_| ())
		};
		if let Err(error) = appended {
			if !super::chain::Unconfirmed::is(&error) {
				partial.set(before);
			}
			return Err(error);
		}
		written += 1;
	}
	Ok(written)
}

/// The recipients of `id` the chain shows as canceled, in the days from the
/// one `since` falls in. A day that cannot be read is an error: the entry
/// stays as it is.
fn already(
	evidence_root: &Path,
	chain: &Chain,
	id: uuid::Uuid,
	since: u64,
) -> std::io::Result<HashSet<String>> {
	let first = super::day::Day::of_epoch(since);
	let mut done = HashSet::new();
	for day in chain.days()?.into_iter().filter(|day| *day >= first) {
		super::verify::walk_day(evidence_root, day, None, |_, record, _| {
			if let Entry::Outcome(outcome) = &record.entry
				&& outcome.spool_id == id
				&& outcome.result == OutcomeKind::Canceled
			{
				done.insert(outcome.recipient.clone());
			}
		})
		.map_err(|at| std::io::Error::new(std::io::ErrorKind::InvalidData, at.to_string()))?;
	}
	Ok(done)
}

#[cfg(test)]
#[path = "cancel_tests.rs"]
mod tests;
