//! The queue worker: drains the outbound spool.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::smtp::address::Address;
use crate::smtp::sink::MessageSink;
use crate::storage::{FsSpool, RecipientStatus, SpoolEntry};

use super::client::DeliveryError;
use super::resolver::Connector;
use conversation::Conversation;

#[path = "worker_conversation.rs"]
mod conversation;
#[path = "worker_reports.rs"]
mod reports;

/// Default give-up window: a message older than this is bounced (RFC 5321
/// §4.5.4.1 guidance of 4–5 days). The bound is by message age, not attempt
/// count, so a recipient down for hours does not lose mail. Operator-tunable.
const DEFAULT_MAX_AGE_SECS: u64 = 5 * 86_400;

/// Outbound queue worker.
pub struct Worker {
	spool: FsSpool,
	connector: Arc<dyn Connector>,
	ehlo_hostname: String,
	/// Where bounces are delivered. `None` drops them with a warning.
	bounce_sink: Option<Arc<dyn MessageSink>>,
	/// MTA-STS policy store plus the DNS used for discovery.
	mta_sts: Option<(
		Arc<crate::mtasts::PolicyStore>,
		Arc<dyn crate::spf::DnsLookup>,
	)>,
	/// Test override for "now" (epoch seconds); 0 means the real clock.
	clock: std::sync::atomic::AtomicU64,
	/// Counters for outbound delivery outcomes (relayed, deferred, bounced).
	metrics: Option<Arc<crate::metrics::Metrics>>,
	/// Webhook for delivery-failure events (fire-and-forget, advisory).
	webhook: Option<Arc<crate::webhook::Webhook>>,
	/// Give-up window in seconds: a message older than this is bounced.
	max_age_secs: u64,
	/// Suppression list: recipients that hard-bounced are not retried.
	suppression: Option<super::SuppressionList>,
	/// Outbound transport rules (relay/socks/direct/fail). Empty = direct MX.
	transports: Vec<crate::config::Transport>,
	/// DNSSEC-validating resolver for DANE TLSA lookups. `None` disables DANE
	/// (delivery stays opportunistic).
	dane_dns: Option<Arc<dyn crate::spf::DnsLookup>>,
	/// STARTTLS authentication mode for unmandated, non-DANE delivery. Defaults
	/// to strict PKIX (the secure default); see [`crate::config::OutboundTls`].
	outbound_tls: crate::config::OutboundTls,
	/// Data directory whose TLS-RPT journal records each direct delivery's TLS
	/// outcome. `None` records nothing (sending reports is turned off).
	tlsrpt_dir: Option<std::path::PathBuf>,
	/// When pending recipients are retried and the delay warning is sent.
	schedule: super::RetrySchedule,
	/// Draws the spread factor of each wait; replaced in tests so the
	/// schedule is deterministic.
	jitter: fn() -> f64,
}

impl Worker {
	/// Create a worker draining `spool` through `connector`.
	pub fn new(spool: FsSpool, connector: Arc<dyn Connector>, ehlo_hostname: &str) -> Self {
		Worker {
			spool,
			connector,
			ehlo_hostname: ehlo_hostname.to_string(),
			bounce_sink: None,
			mta_sts: None,
			clock: std::sync::atomic::AtomicU64::new(0),
			metrics: None,
			webhook: None,
			max_age_secs: DEFAULT_MAX_AGE_SECS,
			suppression: None,
			transports: Vec::new(),
			dane_dns: None,
			outbound_tls: crate::config::OutboundTls::default(),
			tlsrpt_dir: None,
			schedule: super::RetrySchedule::default(),
			jitter: super::schedule::random_factor,
		}
	}

	/// Retry pending recipients and warn about delays on this schedule
	/// instead of the default one.
	pub fn with_retry_schedule(mut self, schedule: super::RetrySchedule) -> Self {
		self.schedule = schedule;
		self
	}

	/// When a recipient that has failed `attempts` times is next due.
	fn retry_at(&self, now: u64, attempts: u32) -> u64 {
		now.saturating_add(self.schedule.wait(attempts, (self.jitter)()))
	}

	/// Record the TLS outcome of every direct MX delivery attempt in the
	/// TLS-RPT session journal under `data_dir`.
	pub fn with_tlsrpt(mut self, data_dir: &std::path::Path) -> Self {
		self.tlsrpt_dir = Some(data_dir.to_path_buf());
		self
	}

	/// Set the outbound STARTTLS authentication mode for unmandated, non-DANE
	/// delivery. The default is strict PKIX; opportunistic accepts any
	/// certificate (encryption without authentication).
	pub fn with_outbound_tls(mut self, mode: crate::config::OutboundTls) -> Self {
		self.outbound_tls = mode;
		self
	}

	/// Enforce outbound DANE (RFC 7672) using this DNSSEC-validating resolver
	/// for TLSA lookups. Without it, delivery stays opportunistic.
	pub fn with_dane(mut self, dns: Arc<dyn crate::spf::DnsLookup>) -> Self {
		self.dane_dns = Some(dns);
		self
	}

	/// DNSSEC-validated TLSA records for an MX host, queried at `_25._tcp.<host>`
	/// (RFC 7672 §3). `Ok(vec![])` when DANE is disabled, the host publishes
	/// none, or the response is not authenticated — the lookup only ever returns
	/// trusted records, so an empty result means "no DANE" (opportunistic TLS).
	///
	/// A transient TLSA lookup failure is propagated as `Err`, never collapsed
	/// into an empty result: treating a temporary resolver error as "no DANE"
	/// would silently downgrade a host that does publish TLSA, defeating the
	/// downgrade protection DANE exists for (RFC 7672 §2.1). The caller defers
	/// delivery in that case instead.
	async fn tlsa_for(
		&self,
		mx_host: &str,
	) -> Result<Vec<crate::dane::tlsa::TlsaRecord>, crate::spf::DnsFailure> {
		match &self.dane_dns {
			Some(dns) => dns.tlsa(&format!("_25._tcp.{mx_host}")).await,
			None => Ok(Vec::new()),
		}
	}

	/// Route outbound mail through these transport rules (relay/socks/direct/
	/// fail). Empty (the default) delivers everything directly via MX.
	pub fn with_transports(mut self, transports: Vec<crate::config::Transport>) -> Self {
		self.transports = transports;
		self
	}

	/// Override the give-up window (seconds). A message older than this is
	/// bounced; zero falls back to the default.
	pub fn with_max_age(mut self, secs: u64) -> Self {
		if secs > 0 {
			self.max_age_secs = secs;
		}
		self
	}

	/// Skip (and record) recipients on this suppression list.
	pub fn with_suppression(mut self, suppression: super::SuppressionList) -> Self {
		self.suppression = Some(suppression);
		self
	}

	/// Fire delivery-failure events to this webhook.
	pub fn with_webhook(mut self, webhook: Arc<crate::webhook::Webhook>) -> Self {
		self.webhook = Some(webhook);
		self
	}

	/// Record outbound delivery outcomes to these process metrics.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Enforce MTA-STS policies on outbound delivery.
	pub fn with_mta_sts(
		mut self,
		store: Arc<crate::mtasts::PolicyStore>,
		dns: Arc<dyn crate::spf::DnsLookup>,
	) -> Self {
		self.mta_sts = Some((store, dns));
		self
	}

	#[cfg(test)]
	fn set_jitter(&mut self, jitter: fn() -> f64) {
		self.jitter = jitter;
	}

	#[cfg(test)]
	fn set_now(&self, epoch: u64) {
		self.clock
			.store(epoch, std::sync::atomic::Ordering::Relaxed);
	}

	fn now_epoch(&self) -> u64 {
		let test_clock = self.clock.load(std::sync::atomic::Ordering::Relaxed);
		if test_clock != 0 {
			return test_clock;
		}
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	}

	/// Bump an outbound counter, if metrics are configured.
	fn metric(&self, bump: impl FnOnce(&crate::metrics::Metrics)) {
		if let Some(metrics) = &self.metrics {
			bump(metrics);
		}
	}

	/// Deliver bounces for failed mail through this sink.
	pub fn with_bounce_sink(mut self, sink: Arc<dyn MessageSink>) -> Self {
		self.bounce_sink = Some(sink);
		self
	}

	/// Age in seconds of a spooled message, derived from its UUIDv7 id (the id
	/// encodes its creation time, so age survives restarts without extra state).
	/// Time an operator held the message is subtracted by the caller.
	fn message_age(&self, id: uuid::Uuid, now: u64) -> u64 {
		let created = id.get_timestamp().map(|ts| ts.to_unix().0).unwrap_or(now);
		now.saturating_sub(created)
	}

	/// Run forever, scanning the spool periodically.
	pub async fn run(self: Arc<Self>, interval: Duration) {
		loop {
			if let Err(error) = self.pass().await {
				tracing::warn!(%error, "queue pass failed");
			}
			tokio::time::sleep(interval).await;
		}
	}

	/// One pass over the spool. Returns the number of entries that had at
	/// least one recipient delivered in this pass.
	pub async fn pass(&self) -> std::io::Result<usize> {
		let now = self.now_epoch();
		let mut delivered = 0;
		for id in self.spool.list()? {
			// The CLI edits entries on disk while this runs, so `held` and
			// `next_attempt` are read from the file on every pass, never kept in
			// memory. Skip held entries and entries still backing off.
			match self.spool.load_envelope(id) {
				Ok(envelope) if envelope.held.is_some() || envelope.next_attempt > now => continue,
				Ok(_) => {}
				Err(error) => {
					tracing::warn!(%id, %error, "cannot read spool entry");
					continue;
				}
			}
			if self.process(id, now).await? {
				delivered += 1;
			}
		}
		Ok(delivered)
	}

	/// Attempt the due recipients of one entry, one conversation per domain,
	/// then settle what is final. Returns whether any recipient was delivered.
	///
	/// Each conversation's outcome is written to the envelope (atomically,
	/// under the spool lock) as soon as it ends, before the next domain is
	/// tried. The only window for a duplicate is between the remote's reply
	/// to DATA and that write: a crash there leaves the recipients of that one
	/// conversation pending, and the restarted worker sends them the message
	/// once more. Recipients of earlier conversations are already recorded and
	/// are not sent again.
	async fn process(&self, id: uuid::Uuid, now: u64) -> std::io::Result<bool> {
		let entry = match self.spool.load(id) {
			Ok(entry) => entry,
			Err(error) => {
				tracing::warn!(%id, %error, "cannot read spool entry");
				return Ok(false);
			}
		};
		let due = self.skip_suppressed(id, &entry, now)?;
		let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
		let mut unparseable = Vec::new();
		for recipient in due {
			match Address::parse(&recipient) {
				Ok(address) => by_domain
					.entry(address.domain().to_string())
					.or_default()
					.push(recipient),
				Err(_) => unparseable.push(recipient),
			}
		}
		let mut delivered = false;
		if !unparseable.is_empty() {
			let reason = DeliveryError::Permanent("unparseable recipient address".into());
			let conversation = Conversation::all(&unparseable, None, reason);
			self.record(id, &entry, &conversation, now)?;
		}
		for (domain, recipients) in by_domain {
			let conversation = self.converse(&entry, &domain, &recipients).await;
			self.record(id, &entry, &conversation, now)?;
			delivered |= conversation
				.results
				.iter()
				.any(|(_, result)| result.is_ok());
		}
		self.finish(id, now, delivered)?;
		Ok(delivered)
	}

	/// Write one conversation's outcome to the envelope, then act on it.
	fn record(
		&self,
		id: uuid::Uuid,
		entry: &SpoolEntry,
		conversation: &Conversation,
		now: u64,
	) -> std::io::Result<()> {
		self.spool.update_envelope(id, |envelope| {
			for (recipient, result) in &conversation.results {
				let mut state = envelope.recipient_state(recipient);
				state.remote = conversation.remote.clone();
				match result {
					Ok(()) => state.status = RecipientStatus::Delivered,
					Err(DeliveryError::Transient(reason)) => {
						state.attempts += 1;
						state.next_attempt = self.retry_at(now, state.attempts);
						state.last_error = Some(reason.clone());
						envelope.last_error = Some(reason.chars().take(512).collect());
					}
					Err(DeliveryError::Permanent(reason)) => {
						state.status = RecipientStatus::Failed;
						state.last_error = Some(reason.clone());
					}
				}
				envelope.set_recipient_state(recipient, state);
			}
			envelope.settle();
		})?;
		self.after_conversation(id, entry, conversation);
		Ok(())
	}

	/// Settle an entry after its conversations: expire it when too old, send
	/// the failure report for recipients that failed, warn about a long
	/// delay, and remove it once no recipient is pending.
	fn finish(&self, id: uuid::Uuid, now: u64, delivered: bool) -> std::io::Result<()> {
		let envelope = self.spool.load_envelope(id)?;
		let age = self.message_age(id, now).saturating_sub(envelope.held_secs);
		if !envelope.pending().is_empty() && age >= self.max_age_secs {
			// Give up by message age, not attempt count: a recipient down for
			// hours must not lose mail (RFC 5321 §4.5.4.1).
			self.expire(id, &envelope.pending())?;
		}
		if delivered {
			self.metric(|m| m.relayed());
		}
		if self.report_failures(id)? {
			self.metric(|m| m.bounced());
		}
		let envelope = self.spool.load_envelope(id)?;
		if envelope.pending().is_empty() {
			return self.spool.remove(id);
		}
		if age >= self.schedule.delay_warning {
			self.warn_delayed(id);
		}
		tracing::debug!(%id, age, "delivery deferred");
		self.metric(|m| m.deferred());
		Ok(())
	}
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "worker_tests_tlsrpt.rs"]
mod tests_tlsrpt;

#[cfg(test)]
#[path = "worker_tests_recipients.rs"]
mod tests_recipients;

#[cfg(test)]
#[path = "worker_tests_classes.rs"]
mod tests_classes;

#[cfg(test)]
#[path = "worker_tests_reports.rs"]
mod tests_reports;

#[cfg(test)]
#[path = "worker_tests_webhook.rs"]
mod tests_webhook;

#[cfg(test)]
#[path = "worker_tests_schedule.rs"]
mod tests_schedule;
