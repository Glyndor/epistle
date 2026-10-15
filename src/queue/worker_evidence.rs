//! The evidence of what happened to each recipient of a message that keeps
//! evidence: delivered (with the reply, the exchanger, the TLS session and
//! whether DANE and MTA-STS applied), bounced, expired or suppressed.

use std::sync::Arc;

use super::Worker;
use crate::evidence::record::{OutcomeKind, TlsSummary};
use crate::evidence::service::{Delivery, EvidenceService};
use crate::queue::client::SessionFacts;
use crate::storage::Envelope;

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

	/// Record one outcome when `envelope` keeps evidence. A failure is
	/// logged: the delivery has happened, and `verify` shows an acceptance
	/// without its outcome.
	pub(super) fn record_outcome(&self, envelope: &Envelope, outcome: Recorded<'_>) {
		let (Some(service), true) = (&self.evidence, envelope.evidence) else {
			return;
		};
		let account = envelope.account.as_deref().unwrap_or_default();
		let retain_days = service
			.retention(account, &envelope.reverse_path, envelope.class)
			.map_or(crate::evidence::policy::DEFAULT_DAYS, |retention| {
				retention.days
			});
		let facts = outcome.facts.cloned().unwrap_or_default();
		let delivery = Delivery {
			spool_id: envelope.id,
			class: envelope.class,
			recipient: outcome.recipient,
			result: outcome.result,
			attempt: outcome.attempt,
			remote: outcome
				.remote
				.filter(|remote| !remote.is_empty() && *remote != "-"),
			reply: facts.reply.as_deref().or(outcome.reply),
			tls: facts
				.tls
				.map(|(version, cipher)| TlsSummary { version, cipher }),
			dane: facts.dane,
			mta_sts: facts.mta_sts.as_deref(),
			retain_days,
		};
		if let Err(error) = service.outcome(&delivery) {
			tracing::warn!(id = %envelope.id, %error, "evidence outcome not recorded");
		}
	}
}
