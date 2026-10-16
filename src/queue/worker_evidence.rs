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

impl Worker {
	/// Record the outcomes of messages that keep evidence through `service`.
	pub fn with_evidence(mut self, service: Arc<EvidenceService>) -> Self {
		self.evidence = Some(service);
		self
	}

	/// Record one outcome when `envelope` keeps evidence. The delivery has
	/// happened, so for mail whose evidence is mandatory an outcome the log
	/// would not take is kept in the envelope and the entry stays in the
	/// queue until it is written, never sent again; the failure is an error
	/// in the log, not a warning.
	pub(super) fn record_outcome(&self, envelope: &Envelope, outcome: Recorded<'_>) {
		let (Some(service), true) = (&self.evidence, envelope.evidence) else {
			return;
		};
		let pending = PendingOutcome {
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
		};
		if let Err(error) = self.write_outcome(service, envelope, &pending) {
			if !envelope.class.evidence_mandatory() {
				tracing::warn!(id = %envelope.id, %error, "evidence outcome not recorded");
				return;
			}
			tracing::error!(
				id = %envelope.id,
				%error,
				"the outcome of a transactional message could not be recorded; it is kept and tried again"
			);
			let kept = self.spool.update_envelope(envelope.id, |stored| {
				stored.outcomes_pending.push(pending);
				stored.last_error = Some("an evidence outcome is waiting to be written".into());
			});
			if let Err(error) = kept {
				tracing::error!(id = %envelope.id, %error, "the outcome could not be kept either");
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
