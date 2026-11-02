//! Delivery routing: local recipients to mailboxes, remote to the queue.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::directory_store::DirectoryHandle;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::crypto::MessageCrypto;
use super::delivery::LocalDelivery;
use super::spool::FsSpool;

/// How long an SRS-return address stays valid (RFC-less convention).
const SRS_MAX_AGE_DAYS: u64 = 14;

/// Splits an accepted message between local mailbox delivery and the
/// outbound spool, according to the directory.
pub struct SplitDelivery {
	directory: DirectoryHandle,
	local: LocalDelivery,
	outbound: FsSpool,
	signer: Option<crate::dkim::PerDomainSigner>,
	rules: Vec<crate::rules::Rule>,
	/// SRS rewriter and our domain, for forwarded (redirected) mail.
	srs: Option<(crate::queue::srs::Srs, String)>,
	/// ARC sealer for forwarded mail, so the next hop can trust our assessment
	/// even when forwarding breaks SPF/DKIM (RFC 8617). Optional and our domain,
	/// used to skip re-sealing a chain we already sealed at inbound accept.
	arc: Option<(Arc<crate::arc::sealer::ArcSealer>, String)>,
	/// Counters for Sieve delivery outcomes (reject, vacation, redirect).
	pub(super) metrics: Option<Arc<crate::metrics::Metrics>>,
	/// Outbound webhook for delivery events (fire-and-forget, advisory).
	webhook: Option<Arc<crate::webhook::Webhook>>,
	/// Records submissions that keep evidence; `None` keeps none.
	pub(super) evidence: Option<Arc<crate::evidence::service::EvidenceService>>,
	/// Which identification and reputation headers the mail this sink
	/// generates gets (a Sieve rejection or a forward-loop notice).
	pub(super) identification: crate::smtp::identification::Policy,
}

impl SplitDelivery {
	/// Create the routing sink rooted at `data_dir` with no at-rest encryption.
	/// The encrypting variant is [`SplitDelivery::new_with_crypto`].
	pub fn new(data_dir: &std::path::Path, directory: DirectoryHandle) -> std::io::Result<Self> {
		Self::new_with_crypto(data_dir, directory, MessageCrypto::disabled())
	}

	/// Create the routing sink rooted at `data_dir`, encrypting stored message
	/// files (local mailboxes and the outbound spool) through `crypto`.
	pub fn new_with_crypto(
		data_dir: &std::path::Path,
		directory: DirectoryHandle,
		crypto: MessageCrypto,
	) -> std::io::Result<Self> {
		let outbound = FsSpool::open_audited(data_dir, crypto.clone())?;
		Ok(SplitDelivery {
			local: LocalDelivery::new_with_crypto(data_dir, directory.clone(), crypto.clone())?,
			outbound,
			directory,
			signer: None,
			rules: Vec::new(),
			srs: None,
			arc: None,
			metrics: None,
			webhook: None,
			evidence: None,
			identification: crate::smtp::identification::Policy::default(),
		})
	}

	/// Apply the server default quota to local copies from every ingress path.
	pub fn with_quota(mut self, default_bytes: u64) -> Self {
		self.local = self.local.with_quota(default_bytes);
		self
	}

	/// Set which identification and reputation headers the mail this sink
	/// generates gets. The same policy the submission paths use.
	pub fn with_identification(mut self, policy: crate::smtp::identification::Policy) -> Self {
		self.identification = policy;
		self
	}

	/// Fire delivery-event notifications to this webhook.
	pub fn with_webhook(mut self, webhook: Arc<crate::webhook::Webhook>) -> Self {
		self.webhook = Some(webhook);
		self
	}

	/// Build a `MessageReceived` event for `recipient` from the raw message.
	fn message_event(recipient: &str, message: &AcceptedMessage) -> crate::webhook::WebhookEvent {
		crate::webhook::WebhookEvent::MessageReceived {
			account: recipient.to_string(),
			from: message.reverse_path.clone(),
			subject: header_of(&message.data, "subject"),
			message_id: header_of(&message.data, "message-id"),
		}
	}

	/// Record Sieve delivery outcomes to these process metrics. The same
	/// handle is also threaded into the inner [`LocalDelivery`] so the
	/// report-ingest hook can count `dmarc_reports_ingested`,
	/// `tlsrpt_reports_ingested`, `dmarc_report_rows_failing`,
	/// `tlsrpt_failed_sessions`, and `reports_dropped`.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics.clone());
		self.local = self.local.with_metrics(metrics);
		self
	}

	/// Sign outbound messages with this DKIM signer. Per-domain
	/// overrides are picked at sign time from the same handle.
	pub fn with_signer(mut self, signer: crate::dkim::PerDomainSigner) -> Self {
		self.signer = Some(signer);
		self
	}

	/// Rewrite the sender of forwarded mail via SRS at `our_domain`, so it
	/// passes SPF at the next hop.
	pub fn with_srs(mut self, srs: crate::queue::srs::Srs, our_domain: impl Into<String>) -> Self {
		self.srs = Some((srs, our_domain.into()));
		self
	}

	/// Seal forwarded mail into our ARC chain at `our_domain`, so the next hop
	/// can trust this hop's authentication assessment (RFC 8617). Our domain is
	/// taken from the sealer so we can skip re-sealing a chain we already sealed.
	pub fn with_arc_sealer(mut self, sealer: Arc<crate::arc::sealer::ArcSealer>) -> Self {
		let domain = sealer.domain().to_string();
		self.arc = Some((sealer, domain));
		self
	}

	/// Apply these delivery rules to locally delivered mail.
	pub fn with_rules(mut self, rules: Vec<crate::rules::Rule>) -> Self {
		self.rules = rules;
		self
	}

	/// The mailbox local delivery should target for `message`, per the rules:
	/// an explicit mailbox, or `Junk` for a junk verdict, else INBOX (`None`).
	fn target_mailbox(&self, message: &AcceptedMessage) -> Option<String> {
		let sender_domain = message
			.reverse_path
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_ascii_lowercase());
		let rule = crate::rules::evaluate(&self.rules, &message.data, sender_domain.as_deref())?;
		match &rule.mailbox {
			Some(mailbox) => Some(mailbox.clone()),
			None if rule.junk => Some("Junk".to_string()),
			None => None,
		}
	}
}

/// What happened to the recipients delivered on this server.
#[derive(Debug, Clone)]
pub(super) struct LocalDone {
	/// The recipients that resolved to an account or an alias.
	pub recipients: Vec<String>,
	/// Why a rule of theirs rejected the message, when one did.
	pub reject: Option<String>,
}

/// The value of header `field` from a raw message's header block, if present.
fn header_of(data: &[u8], field: &str) -> Option<String> {
	let text = String::from_utf8_lossy(data);
	let headers = text.split("\r\n\r\n").next().unwrap_or(&text);
	for line in headers.split("\r\n") {
		if let Some((name, value)) = line.split_once(':')
			&& name.trim().eq_ignore_ascii_case(field)
		{
			return Some(value.trim().to_string());
		}
	}
	None
}

mod evidence;
mod forward;
mod outbound;
mod route;
mod seal;
mod sink;

#[cfg(test)]
mod tests;
