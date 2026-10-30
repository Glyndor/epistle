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

	/// ARC headers to prepend to a forwarded copy of `data`, or `None` when no
	/// sealer is configured, when our domain already sealed the latest instance
	/// (skip the duplicate set), or when the message cannot be sealed.
	///
	/// Forward sealing stays synchronous: the chain-validation status comes from
	/// the pure [`crate::arc::chain::chain_status`] (the prior chain's recorded
	/// `cv`), never the async, DNS-backed `arc::validate::validate`. A message
	/// with no prior chain — the common case — yields `cv=none` with no lookup;
	/// a present chain reuses its own recorded status structurally rather than
	/// re-running cryptographic verification in this sync delivery path.
	pub(super) fn arc_seal(&self, data: &[u8]) -> Option<String> {
		let (sealer, our_domain) = self.arc.as_ref()?;
		let prior = crate::arc::chain::extract(data)
			.ok()
			.flatten()
			.unwrap_or_default();
		// No double seal: if our domain already authored the latest instance
		// (e.g. inbound mail we sealed at accept), do not add a second set.
		if let Some(top) = prior.last()
			&& crate::arc::chain::tag(&top.seal, "d")
				.is_some_and(|d| d.eq_ignore_ascii_case(our_domain))
		{
			return None;
		}
		// cv reflects the prior chain: none when fresh, else its recorded status
		// (a structurally broken chain extracts to empty, so seals as a fresh
		// chain — never an invalid set). This keeps sealing sync (no DNS).
		let cv = if prior.is_empty() {
			crate::arc::chain::ChainValidation::None
		} else {
			crate::arc::chain::chain_status(&prior)
				.unwrap_or(crate::arc::chain::ChainValidation::Fail)
		};
		// Reuse this message's Authentication-Results as our hop's summary, or a
		// minimal "none" when the message carries none.
		let auth_results =
			header_of(data, "authentication-results").unwrap_or_else(|| "none".to_string());
		sealer.seal(data, &auth_results, &prior, cv)
	}

	/// The envelope sender to use for mail forwarded to `redirect`: an SRS
	/// rewrite of the original sender when SRS is enabled, else the original.
	pub(super) fn forward_sender(&self, original: &str) -> String {
		if original.is_empty() {
			return String::new();
		}
		let Some((srs, our_domain)) = &self.srs else {
			return original.to_string();
		};
		let Some((local, domain)) = original.rsplit_once('@') else {
			return original.to_string();
		};
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		srs.forward(local, domain, our_domain, now_days)
	}

	/// If `recipient` is a valid SRS-return address at our domain, the original
	/// sender it should be forwarded back to; otherwise `None`.
	fn srs_return(&self, recipient: &str) -> Option<String> {
		let (srs, our_domain) = self.srs.as_ref()?;
		let (local, domain) = recipient.rsplit_once('@')?;
		if !domain.eq_ignore_ascii_case(our_domain) {
			return None;
		}
		let now_days = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs() / 86_400)
			.unwrap_or(0);
		let (orig_local, orig_domain) = srs.reverse(local, now_days, SRS_MAX_AGE_DAYS)?;
		Some(format!("{orig_local}@{orig_domain}"))
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

impl MessageSink for SplitDelivery {
	/// Mail from elsewhere: whatever `TLS-Required` it carries is not ours
	/// to honour, so it never reaches a copy we store or forward.
	fn deliver(&self, mut message: AcceptedMessage) -> Result<(), SinkError> {
		message.data = crate::queue::tls_required::strip(message.data);
		self.route_classed(
			message,
			uuid::Uuid::now_v7(),
			None,
			&BTreeMap::new(),
			(crate::evidence::MailClass::Personal, None),
			None,
		)
	}

	/// A report the server wrote: once it is in a local mailbox, a later step
	/// (a redirect, a vacation reply) that fails is logged and not returned,
	/// because the caller would send the report again and fill the mailbox
	/// with copies.
	fn deliver_report(&self, mut message: AcceptedMessage) -> Result<(), SinkError> {
		message.data = crate::queue::tls_required::strip(message.data);
		let mut done = None;
		let routed = self.route_reporting(
			message,
			(uuid::Uuid::now_v7(), None, &BTreeMap::new()),
			(crate::evidence::MailClass::Personal, None),
			None,
			&mut done,
		);
		match (routed, done) {
			(Err(error), Some(_)) => {
				tracing::warn!(%error, "a report reached a mailbox and a later step failed; not repeated");
				Ok(())
			}
			(routed, _) => routed,
		}
	}

	/// Mail one of our accounts sends: only the server's own inspection may
	/// speak in the attachment warning header, so whatever the sender wrote
	/// there is dropped before any copy is stored, queued or signed.
	fn submit(
		&self,
		mut message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		submission: &crate::smtp::sink::Submission,
	) -> Result<(), SinkError> {
		crate::smtp::trace::strip_headers_in_place(
			&mut message.data,
			&[crate::antispam::attachments::policy::WARNING_HEADER],
		);
		match self.evidence_for(account, &message, submission.class)? {
			Some(retention) => {
				self.route_with_evidence(message, queue_id, account, submission, retention)
			}
			None => self.route_classed(
				message,
				queue_id,
				Some(account),
				&submission.extra,
				(submission.class, None),
				None,
			),
		}
	}
}

impl SplitDelivery {
	/// Route `message`: local recipients to their mailboxes, the rest to the
	/// outbound spool under `queue_id`, DKIM-signed when a signer is set.
	/// `account` is the local account that submitted, when known; `extra` is
	/// the caller-supplied correlation map (the API may attach one).
	/// `presigned` is the exact outbound copy when the caller recorded
	/// evidence over it.
	pub(super) fn route_classed(
		&self,
		message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: Option<&str>,
		extra: &BTreeMap<String, String>,
		class: (crate::evidence::MailClass, Option<u32>),
		presigned: Option<Vec<u8>>,
	) -> Result<(), SinkError> {
		self.route_reporting(
			message,
			(queue_id, account, extra),
			class,
			presigned,
			&mut None,
		)
	}

	/// [`route_classed`](Self::route_classed), telling `done` which
	/// recipients were delivered locally and whether a rule rejected them,
	/// as soon as that is so: a later failure does not undo it.
	pub(super) fn route_reporting(
		&self,
		message: AcceptedMessage,
		(queue_id, account, extra): (uuid::Uuid, Option<&str>, &BTreeMap<String, String>),
		(class, evidence): (crate::evidence::MailClass, Option<u32>),
		presigned: Option<Vec<u8>>,
		done: &mut Option<LocalDone>,
	) -> Result<(), SinkError> {
		let mut local = Vec::new();
		let mut remote = Vec::new();
		let mut srs_returns = Vec::new();
		for recipient in &message.recipients {
			// An SRS-return address forwards the (bounce) message back to the
			// original sender it encodes.
			if let Some(original) = self.srs_return(recipient) {
				srs_returns.push(original);
				continue;
			}
			let address = Address::parse(recipient).map_err(|_| {
				SinkError::Unavailable(format!("unparseable recipient {recipient}"))
			})?;
			match self.directory.current().resolve(&address) {
				// An account or a multi-target alias delivers locally; the alias
				// is expanded to its members by `LocalDelivery`.
				Resolution::Account(_) | Resolution::Alias(_) => local.push(recipient.clone()),
				Resolution::NotLocal => remote.push(recipient.clone()),
				// The session rejected unknown local users; drift here is
				// a logic error and the whole delivery fails closed.
				Resolution::UnknownUser => {
					return Err(self.directory.current().unresolved(
						&address,
						format!("recipient {recipient} no longer resolves"),
					));
				}
			}
		}

		if !local.is_empty() {
			let mailbox = message
				.mailbox
				.clone()
				.or_else(|| self.target_mailbox(&message));
			let local_message = AcceptedMessage {
				recipients: local,
				..message.clone()
			};
			let delivered = self
				.local
				.deliver_routed(&local_message, mailbox.as_deref())?;
			*done = Some(LocalDone {
				recipients: local_message.recipients.clone(),
				reject: delivered.reject.clone(),
			});
			// Notify the webhook for messages that actually landed (not rejected).
			if delivered.reject.is_none()
				&& let Some(webhook) = &self.webhook
			{
				for recipient in &local_message.recipients {
					let webhook = webhook.clone();
					let event = Self::message_event(recipient, &local_message);
					tokio::spawn(async move { webhook.notify(&event).await });
				}
			}
			if let Some(reason) = delivered.reject {
				if let Some(metrics) = &self.metrics {
					metrics.sieve_rejected();
				}
				let hostname = local_message
					.recipients
					.first()
					.and_then(|r| r.rsplit_once('@'))
					.map(|(_, domain)| domain.to_string())
					.unwrap_or_else(|| "localhost".to_string());
				// Recipients with NOTIFY=NEVER (RFC 3461) get no failure DSN.
				let dsn_recipients: Vec<String> = local_message
					.recipients
					.iter()
					.filter(|r| !local_message.no_dsn.contains(r))
					.cloned()
					.collect();
				if let Some(bounce) = (!dsn_recipients.is_empty())
					.then(|| {
						crate::queue::bounce::build(
							&hostname,
							&message.reverse_path,
							&dsn_recipients,
							&reason,
							&message.data,
							std::time::SystemTime::now(),
							self.identification.system_auto_submitted,
						)
					})
					.flatten()
				{
					self.outbound
						.store(&bounce, account, extra)
						.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				}
			}
			self.queue_redirects(&message, delivered.redirects)?;
			self.bounce_loops(&message, &delivered.looped)?;
			for mut reply in delivered.replies {
				self.sign_reply(&mut reply);
				self.outbound
					.store(&reply, account, extra)
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				if let Some(metrics) = &self.metrics {
					metrics.vacation_sent();
				}
			}
		}
		// Forward SRS-return (bounce) messages back to the original senders.
		for original in srs_returns {
			let returned = AcceptedMessage {
				reverse_path: message.reverse_path.clone(),
				recipients: vec![original],
				data: message.data.clone(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			};
			self.outbound
				.store(&returned, account, extra)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		if !remote.is_empty() {
			let mut outbound_message = AcceptedMessage {
				recipients: remote,
				..message
			};
			// With evidence the acceptance was recorded over the signed bytes
			// already: queue exactly those, never a second signature.
			match presigned {
				Some(signed) => outbound_message.data = signed,
				None => self.sign_outbound(&mut outbound_message),
			}
			// The acceptance was recorded before routing: the queue entry
			// only has to say so, so its outcomes are recorded too.
			let recorded = |_: &[u8]| Ok(());
			let options = super::spool::StoreOptions {
				account,
				extra,
				class,
				evidence: evidence.map(|_| &recorded as &dyn Fn(&[u8]) -> std::io::Result<()>),
				retain_days: evidence.unwrap_or(0),
			};
			self.outbound
				.store_with(&outbound_message, queue_id, &options)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		Ok(())
	}

	/// Store `message` in the outbound spool.
	pub(super) fn store_outbound(&self, message: &AcceptedMessage) -> Result<(), SinkError> {
		self.outbound
			.store(message, None, &BTreeMap::new())
			.map(|_| ())
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}

	/// DKIM-sign relayed mail so receivers can verify our domain. The signer
	/// returns the DKIM-Signature header line; it is prepended to the body
	/// in a single allocation, so the body is moved, not copied.
	pub(super) fn sign_outbound(&self, message: &mut AcceptedMessage) {
		if let std::borrow::Cow::Owned(data) =
			crate::util::header_block::outbound_crlf(&message.data)
		{
			message.data = data;
		}
		if let Some(signer) = &self.signer
			&& let Some(domain) = self.signing_domain(message)
			&& let Some(header) = signer.sign(&domain, &message.data)
		{
			let header_bytes = header.as_bytes();
			let mut signed = Vec::with_capacity(header_bytes.len() + message.data.len());
			signed.extend_from_slice(header_bytes);
			signed.append(&mut message.data);
			message.data = signed;
		}
	}

	/// DKIM-sign an auto-reply the server writes itself: it has a null
	/// reverse-path, so `d=` is the domain of its From, the account's own.
	/// The signer returns only the DKIM-Signature header line; we prepend
	/// it to the body in a single allocation sized to the combined length
	/// so the body is moved, not copied.
	fn sign_reply(&self, reply: &mut AcceptedMessage) {
		reply.data = crate::util::header_block::frame_generated(std::mem::take(&mut reply.data));
		if let Some(signer) = &self.signer
			&& let Some(domain) = self.signing_domain(reply)
			&& let Some(header) = signer.sign(&domain, &reply.data)
		{
			let header_bytes = header.as_bytes();
			let mut signed = Vec::with_capacity(header_bytes.len() + reply.data.len());
			signed.extend_from_slice(header_bytes);
			signed.append(&mut reply.data);
			reply.data = signed;
		}
	}

	/// The `d=` for an outbound message: the domain of its single From
	/// header when the key is published for it, so DMARC aligns with the
	/// domain the reader sees; otherwise the envelope domain.
	fn signing_domain(&self, message: &AcceptedMessage) -> Option<String> {
		let envelope = message
			.reverse_path
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_ascii_lowercase());
		match crate::dmarc::author::author_domain(&message.data) {
			crate::dmarc::author::AuthorDomain::One(from)
				if self.directory.current().hosts_domain(&from) =>
			{
				Some(from)
			}
			crate::dmarc::author::AuthorDomain::One(from) => {
				if let Some(envelope) = &envelope {
					tracing::info!(
						%from,
						%envelope,
						"no DKIM key for the From domain; signing for the envelope domain, so DMARC will not align"
					);
				}
				envelope
			}
			_ => envelope,
		}
	}
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

#[cfg(test)]
mod tests;
