//! A queued message taken out of the queue leaves a record.
//!
//! An acceptance whose message an operator removed would otherwise stay in
//! the log with no ending, as if the queue still held it, and nothing would
//! say who stopped it. Each recipient still waiting gets a `canceled` outcome
//! before the entry goes, so the message can be shown whole and what became
//! of it is on record.

use std::path::Path;

use super::chain::Chain;
use super::record::{Entry, Outcome, OutcomeKind};
use crate::storage::{Envelope, RecipientStatus};

/// What the outcome says happened to the message.
pub const REASON: &str = "removed from the queue before it was delivered";

/// Record a `canceled` outcome for every recipient of `envelope` still
/// waiting, when the entry keeps evidence. Returns how many were written.
/// The entry must not be removed unless this returned `Ok`.
pub fn record(evidence_root: &Path, envelope: &Envelope) -> std::io::Result<usize> {
	if !envelope.evidence {
		return Ok(0);
	}
	let chain = Chain::open(evidence_root)?;
	let mut written = 0;
	for recipient in &envelope.recipients {
		let state = envelope.recipient_state(recipient);
		if state.status != RecipientStatus::Pending {
			continue;
		}
		chain.append(Entry::Outcome(Outcome {
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
		}))?;
		written += 1;
	}
	Ok(written)
}
