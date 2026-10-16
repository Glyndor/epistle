//! The evidence of what happened to each recipient of a message that keeps
//! evidence: delivered (with the reply, the exchanger, the TLS session and
//! whether DANE and MTA-STS applied), bounced, expired or suppressed.

use std::sync::Arc;

use super::Worker;
use crate::evidence::record::{OutcomeKind, TlsSummary};
use crate::evidence::service::{Delivery, EvidenceService};
use crate::queue::client::SessionFacts;
use crate::storage::{Envelope, PendingOutcome};

/// One outcome to record.
pub(super) struct Recorded<'a> {
	pub(super) recipient: &'a str,
	pub(super) result: OutcomeKind,
	pub(super) attempt: u32,
	pub(super) remote: Option<&'a str>,
	pub(super) reply: Option<&'a str>,
	pub(super) facts: Option<&'a SessionFacts>,
}

/// The outcome as it is kept in an envelope.
fn pending_from(outcome: &Recorded<'_>) -> PendingOutcome {
	PendingOutcome {
		recipient: outcome.recipient.to_string(),
		result: outcome.result,
		attempt: outcome.attempt,
		remote: outcome
			.remote
			.filter(|remote| !remote.is_empty() && *remote != "-")
			.map(String::from),
		reply: outcome
			.facts
			.and_then(|facts| facts.reply.clone())
			.or_else(|| outcome.reply.map(String::from)),
		tls: outcome.facts.and_then(|facts| facts.tls.clone()),
		dane: outcome.facts.is_some_and(|facts| facts.dane),
		mta_sts: outcome.facts.and_then(|facts| facts.mta_sts.clone()),
	}
}

/// Note in `envelope`, to be saved with the state of the delivery it comes
/// from, that this outcome is owed to the evidence log. Only for entries
/// whose evidence is mandatory; the others lose nothing the log requires.
pub(super) fn intend(envelope: &mut Envelope, outcome: &Recorded<'_>) {
	if !envelope.evidence || !envelope.class.evidence_mandatory() {
		return;
	}
	let pending = pending_from(outcome);
	if !envelope.outcomes_pending.contains(&pending) {
		envelope.outcomes_pending.push(pending);
	}
	envelope.last_error = Some("an evidence outcome is waiting to be written".into());
}

impl Worker {
	/// Record the outcomes of messages that keep evidence through `service`.
	pub fn with_evidence(mut self, service: Arc<EvidenceService>) -> Self {
		self.evidence = Some(service);
		self
	}

	/// Write the outcome of a delivery that was made, and let go of the note
	/// kept for it. The note (see [`intend`]) was written to the envelope in
	/// the same step as the delivery itself, so a worker that dies, or a log
	/// that will not take the record, leaves the outcome owed and the entry in
	/// the queue, never sent again. Mail whose evidence is not mandatory is
	/// only warned about.
	pub(super) fn record_outcome(&self, envelope: &Envelope, outcome: Recorded<'_>) {
		let (Some(service), true) = (&self.evidence, envelope.evidence) else {
			return;
		};
		let pending = pending_from(&outcome);
		match self.write_outcome(service, envelope, &pending) {
			Ok(()) => {
				let _ = self.spool.update_envelope(envelope.id, |stored| {
					stored.outcomes_pending.retain(|kept| *kept != pending);
					if stored.outcomes_pending.is_empty() {
						stored.last_error = None;
					}
				});
			}
			Err(error) if envelope.class.evidence_mandatory() => {
				tracing::error!(
					id = %envelope.id,
					%error,
					"the outcome of a transactional message could not be recorded; it is kept and tried again"
				);
			}
			Err(error) => {
				tracing::warn!(id = %envelope.id, %error, "evidence outcome not recorded");
			}
		}
	}

	/// Write every outcome `envelope` is owed, for an entry that is no longer
	/// in the queue to keep them. Best effort: the log is what is left.
	pub(super) fn write_owed(&self, envelope: &Envelope) {
		let (Some(service), true) = (&self.evidence, envelope.evidence) else {
			return;
		};
		for pending in &envelope.outcomes_pending {
			if let Err(error) = self.write_outcome(service, envelope, pending) {
				tracing::error!(id = %envelope.id, %error, "an outcome of a removed entry could not be recorded");
			}
		}
	}

	/// Write one outcome through `service`.
	fn write_outcome(
		&self,
		service: &EvidenceService,
		envelope: &Envelope,
		outcome: &PendingOutcome,
	) -> std::io::Result<()> {
		// The outcome keeps what the acceptance was given, not what the
		// policy says by the time it arrives; an envelope from before the
		// acceptance's days were kept in it follows the policy.
		let retain_days = match envelope.retain_days {
			0 => service
				.retention(
					envelope.account.as_deref().unwrap_or_default(),
					&envelope.reverse_path,
					envelope.class,
				)
				.map_or(crate::evidence::policy::DEFAULT_DAYS, |retention| {
					retention.days
				}),
			days => days,
		};
		service.outcome(&Delivery {
			spool_id: envelope.id,
			class: envelope.class,
			recipient: &outcome.recipient,
			result: outcome.result,
			attempt: outcome.attempt,
			remote: outcome.remote.as_deref(),
			reply: outcome.reply.as_deref(),
			tls: outcome
				.tls
				.clone()
				.map(|(version, cipher)| TlsSummary { version, cipher }),
			dane: outcome.dane,
			mta_sts: outcome.mta_sts.as_deref(),
			retain_days,
		})
	}

	/// Write the outcomes that could not be written when they happened, and
	/// let an entry that waited only for them go. Called at the start of
	/// each pass.
	pub(super) fn write_waiting_outcomes(&self) {
		let Some(service) = &self.evidence else {
			return;
		};
		let Ok(ids) = self.spool.list() else {
			return;
		};
		for id in ids {
			let Ok(envelope) = self.spool.load_envelope(id) else {
				continue;
			};
			if envelope.outcomes_pending.is_empty() {
				continue;
			}
			let mut written = Vec::new();
			for outcome in &envelope.outcomes_pending {
				match self.write_outcome(service, &envelope, outcome) {
					Ok(()) => written.push(outcome.clone()),
					Err(error) => {
						tracing::warn!(%id, %error, "an evidence outcome is still waiting to be written");
						break;
					}
				}
			}
			if written.is_empty() {
				continue;
			}
			// Under the lock `finish` takes: no conversation of this entry is
			// being settled while its note is dropped and the entry let go.
			let _settling = self
				.settling
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner());
			let Ok(updated) = self.spool.update_envelope(id, |stored| {
				stored
					.outcomes_pending
					.retain(|kept| !written.contains(kept));
				if stored.outcomes_pending.is_empty() {
					stored.last_error = None;
				}
			}) else {
				continue;
			};
			if updated.outcomes_pending.is_empty() && updated.pending().is_empty() {
				let _ = self.spool.remove(id);
			}
		}
	}
}
