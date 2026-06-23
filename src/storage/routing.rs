//! Delivery routing: local recipients to mailboxes, remote to the queue.

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
	signer: Option<crate::dkim::ReloadableSigner>,
	rules: Vec<crate::rules::Rule>,
	/// SRS rewriter and our domain, for forwarded (redirected) mail.
	srs: Option<(crate::queue::srs::Srs, String)>,
	/// ARC sealer for forwarded mail, so the next hop can trust our assessment
	/// even when forwarding breaks SPF/DKIM (RFC 8617). Optional and our domain,
	/// used to skip re-sealing a chain we already sealed at inbound accept.
	arc: Option<(Arc<crate::arc::sealer::ArcSealer>, String)>,
	/// Counters for Sieve delivery outcomes (reject, vacation, redirect).
	metrics: Option<Arc<crate::metrics::Metrics>>,
	/// Outbound webhook for delivery events (fire-and-forget, advisory).
	webhook: Option<Arc<crate::webhook::Webhook>>,
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
		Ok(SplitDelivery {
			local: LocalDelivery::new_with_crypto(data_dir, directory.clone(), crypto.clone())?,
			outbound: FsSpool::open_with_crypto(data_dir, crypto)?,
			directory,
			signer: None,
			rules: Vec::new(),
			srs: None,
			arc: None,
			metrics: None,
			webhook: None,
		})
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

	/// Record Sieve delivery outcomes to these process metrics.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Sign outbound messages with this (hot-swappable) DKIM signer.
	pub fn with_signer(mut self, signer: crate::dkim::ReloadableSigner) -> Self {
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
	fn arc_seal(&self, data: &[u8]) -> Option<String> {
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
	fn forward_sender(&self, original: &str) -> String {
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

impl MessageSink for SplitDelivery {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
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
					return Err(SinkError::Unavailable(format!(
						"recipient {recipient} no longer resolves"
					)));
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
						)
					})
					.flatten()
				{
					self.outbound
						.store(&bounce)
						.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				}
			}
			// Queue Sieve redirects, preserving the (non-null) original sender.
			// ARC-seal the forwarded copy once, shared across every target.
			let forward_data = match self.arc_seal(&message.data) {
				Some(arc_headers) => {
					let mut sealed = arc_headers.into_bytes();
					sealed.extend_from_slice(&message.data);
					sealed
				}
				None => message.data.clone(),
			};
			for address in delivered.redirects {
				let forwarded = AcceptedMessage {
					reverse_path: self.forward_sender(&message.reverse_path),
					recipients: vec![address],
					data: forward_data.clone(),
					require_tls: false,
					mailbox: None,
					no_dsn: Vec::new(),
				};
				self.outbound
					.store(&forwarded)
					.map_err(|error| SinkError::Unavailable(error.to_string()))?;
				if let Some(metrics) = &self.metrics {
					metrics.forwarded();
				}
			}
			for reply in delivered.replies {
				self.outbound
					.store(&reply)
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
				no_dsn: Vec::new(),
			};
			self.outbound
				.store(&returned)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		if !remote.is_empty() {
			let mut outbound_message = AcceptedMessage {
				recipients: remote,
				..message
			};
			// Sign relayed mail so receivers can verify our domain.
			if let Some(signer) = &self.signer
				&& let Some((_, domain)) = outbound_message.reverse_path.rsplit_once('@')
				&& let Some(header) = signer.current().sign(domain, &outbound_message.data)
			{
				let mut signed = header.into_bytes();
				signed.extend_from_slice(&outbound_message.data);
				outbound_message.data = signed;
			}
			self.outbound
				.store(&outbound_message)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		Ok(())
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

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
