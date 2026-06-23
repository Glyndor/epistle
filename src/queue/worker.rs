//! The queue worker: drains the outbound spool.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::smtp::address::Address;
use crate::smtp::sink::MessageSink;
use crate::storage::FsSpool;

use super::client::{self, DeliveryError};
use super::resolver::Connector;

/// Base retry delay; attempt n waits `base * 2^n`, capped at one hour.
const BACKOFF_BASE_SECS: u64 = 60;
const BACKOFF_CAP_SECS: u64 = 3600;

/// Default give-up window: a message older than this is bounced (RFC 5321
/// §4.5.4.1 guidance of 4–5 days). The bound is by message age, not attempt
/// count, so a recipient down for hours does not lose mail. Operator-tunable.
const DEFAULT_MAX_AGE_SECS: u64 = 5 * 86_400;

/// Send a "delivery delayed" warning DSN once the message has been queued this
/// long without success (~4 hours), so the sender knows it is still trying.
const DELAY_WARNING_SECS: u64 = 4 * 3600;

/// When attempt number `attempts` may run, given the current time.
fn backoff_until(now_epoch: u64, attempts: u32) -> u64 {
	let delay = BACKOFF_BASE_SECS
		.saturating_mul(1u64 << attempts.min(16))
		.min(BACKOFF_CAP_SECS);
	now_epoch.saturating_add(delay)
}

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
		}
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

	/// Record every recipient of a permanently failed entry on the suppression
	/// list, so future mail to them is not even attempted.
	fn suppress_entry(&self, id: uuid::Uuid) {
		if let Some(suppression) = &self.suppression
			&& let Ok(entry) = self.spool.load(id)
		{
			let account = &entry.envelope.reverse_path;
			for recipient in &entry.envelope.recipients {
				suppression.suppress(recipient);
				// Also record under the sending account so an operator can see
				// per-account bounces.
				if !account.is_empty() {
					suppression.suppress_for(account, recipient);
				}
			}
		}
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
	fn message_age(&self, id: uuid::Uuid, now: u64) -> u64 {
		let created = id.get_timestamp().map(|ts| ts.to_unix().0).unwrap_or(now);
		now.saturating_sub(created)
	}

	/// Send the one-time "delivery delayed" warning DSN for a still-queued entry.
	fn warn_delayed(&self, id: uuid::Uuid, reason: &str) {
		let Ok(entry) = self.spool.load(id) else {
			return;
		};
		if entry.envelope.delay_warned {
			return;
		}
		// NOTIFY=DELAY is not modelled separately; reuse the failure opt-out so a
		// sender that wants no DSNs at all gets no delay warning either.
		let recipients: Vec<String> = entry
			.envelope
			.recipients
			.iter()
			.filter(|r| !entry.envelope.no_dsn.contains(r))
			.cloned()
			.collect();
		if !recipients.is_empty()
			&& let Some(message) = super::bounce::build_delay_warning(
				&self.ehlo_hostname,
				&entry.envelope.reverse_path,
				&recipients,
				reason,
				&entry.data,
				std::time::SystemTime::now(),
			) && let Some(sink) = &self.bounce_sink
			&& let Err(error) = sink.deliver(message)
		{
			tracing::warn!(%id, %error, "delay-warning delivery failed");
		}
		// Mark warned regardless, so it is attempted at most once.
		if let Err(error) = self.spool.mark_delay_warned(id) {
			tracing::warn!(%id, %error, "failed to record delay warning");
		}
	}

	/// Generate and deliver a bounce for a dropped spool entry.
	fn bounce(&self, id: uuid::Uuid, reason: &str) {
		let Ok(entry) = self.spool.load(id) else {
			return;
		};
		// Advisory webhook: notify per recipient that delivery failed.
		if let Some(webhook) = &self.webhook {
			for recipient in &entry.envelope.recipients {
				let webhook = webhook.clone();
				let event = crate::webhook::WebhookEvent::DeliveryFailed {
					recipient: recipient.clone(),
					reason: reason.to_string(),
				};
				tokio::spawn(async move { webhook.notify(&event).await });
			}
		}
		// Recipients with NOTIFY=NEVER get no failure DSN (RFC 3461). If every
		// failed recipient opted out, no bounce is generated at all.
		let dsn_recipients: Vec<String> = entry
			.envelope
			.recipients
			.iter()
			.filter(|r| !entry.envelope.no_dsn.contains(r))
			.cloned()
			.collect();
		if dsn_recipients.is_empty() {
			return;
		}
		let Some(message) = super::bounce::build(
			&self.ehlo_hostname,
			&entry.envelope.reverse_path,
			&dsn_recipients,
			reason,
			&entry.data,
			std::time::SystemTime::now(),
		) else {
			return;
		};
		match &self.bounce_sink {
			Some(sink) => {
				if let Err(error) = sink.deliver(message) {
					tracing::warn!(%id, %error, "bounce delivery failed");
				}
			}
			None => tracing::warn!(%id, "dropping bounce: no bounce sink configured"),
		}
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

	/// One pass over the spool. Returns the number of delivered entries.
	pub async fn pass(&self) -> std::io::Result<usize> {
		let now = self.now_epoch();
		let mut delivered = 0;
		for id in self.spool.list()? {
			// Skip entries whose backoff has not elapsed yet.
			match self.spool.load(id) {
				Ok(entry) if entry.envelope.next_attempt > now => continue,
				Ok(_) => {}
				// Vanished or unreadable: let deliver_entry classify it.
				Err(_) => {}
			}
			match self.deliver_entry(id).await {
				Outcome::Delivered => {
					self.spool.remove(id)?;
					delivered += 1;
					self.metric(|m| m.relayed());
				}
				Outcome::Dropped(reason) => {
					tracing::warn!(%id, %reason, "dropping undeliverable message");
					self.bounce(id, &reason);
					self.suppress_entry(id);
					self.spool.remove(id)?;
					self.metric(|m| m.bounced());
				}
				Outcome::Suppressed => {
					// Every recipient is already suppressed (hard-bounced
					// before): drop silently, with no second bounce.
					tracing::debug!(%id, "dropping message to suppressed recipients");
					self.spool.remove(id)?;
				}
				Outcome::Retry(reason) => {
					let prior = self
						.spool
						.load(id)
						.map(|entry| entry.envelope.attempts)
						.unwrap_or(0);
					let _ = self.spool.record_attempt(id, backoff_until(now, prior + 1));
					let age = self.message_age(id, now);
					if age >= self.max_age_secs {
						// Give up by message age, not attempt count: a recipient
						// down for hours must not lose mail (RFC 5321 §4.5.4.1).
						tracing::warn!(%id, %reason, age, "giving up: message expired");
						self.bounce(id, &reason);
						self.spool.remove(id)?;
						self.metric(|m| m.bounced());
					} else {
						if age >= DELAY_WARNING_SECS {
							self.warn_delayed(id, &reason);
						}
						tracing::debug!(%id, %reason, age, "delivery deferred");
						self.metric(|m| m.deferred());
					}
				}
			}
		}
		Ok(delivered)
	}

	async fn deliver_entry(&self, id: uuid::Uuid) -> Outcome {
		let entry = match self.spool.load(id) {
			Ok(entry) => entry,
			Err(error) => return Outcome::Retry(format!("spool read failed: {error}")),
		};

		// Skip recipients suppressed globally or for this sending account (they
		// hard-bounced before); if that leaves none, drop without a second
		// bounce.
		let account = &entry.envelope.reverse_path;
		let recipients: Vec<&String> = entry
			.envelope
			.recipients
			.iter()
			.filter(|r| {
				self.suppression
					.as_ref()
					.is_none_or(|s| !s.is_suppressed(r) && !s.is_suppressed_for(account, r))
			})
			.collect();
		if recipients.is_empty() {
			return Outcome::Suppressed;
		}

		// Group recipients by domain: one conversation per exchanger.
		let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
		for recipient in recipients {
			let Ok(address) = Address::parse(recipient) else {
				return Outcome::Dropped(format!("unparseable recipient {recipient}"));
			};
			by_domain
				.entry(address.domain().to_string())
				.or_default()
				.push(recipient.clone());
		}

		for (domain, recipients) in by_domain {
			// MTA-STS: an enforce policy constrains MX choice and mandates TLS.
			let policy = match &self.mta_sts {
				Some((store, dns)) => match store.policy(dns.as_ref(), &domain).await {
					Ok(policy) => {
						policy.filter(|policy| policy.mode == crate::mtasts::Mode::Enforce)
					}
					Err(crate::mtasts::PolicyError::Temporary(reason)) => {
						return Outcome::Retry(reason);
					}
					// Malformed/absent policies fall back to opportunistic.
					Err(_) => None,
				},
				None => None,
			};
			// MTA-STS enforce or a sender's REQUIRETLS both mandate verified TLS.
			let require_tls = policy.is_some() || entry.envelope.require_tls;

			// Route this delivery: a configured transport (relay/fail) or direct.
			let sender_account = entry
				.envelope
				.reverse_path
				.rsplit_once('@')
				.map(|(local, _)| local)
				.filter(|local| !local.is_empty());
			let transport =
				crate::config::select_transport(&self.transports, sender_account, &domain);
			let (stream, server_name, auth, tls_required, dane) = match transport {
				Some(rule) if rule.kind == crate::config::TransportKind::Fail => {
					return Outcome::Dropped(format!("transport policy rejects {domain}"));
				}
				Some(rule) if rule.kind == crate::config::TransportKind::Relay => {
					// host/port validated at config load.
					let host = rule.host.clone().unwrap_or_default();
					let port = rule.port.unwrap_or(0);
					let stream = match super::transport::relay_connect(
						&host,
						port,
						rule.socks_proxy.as_deref(),
					)
					.await
					{
						Ok(stream) => stream,
						Err(DeliveryError::Transient(reason)) => return Outcome::Retry(reason),
						Err(DeliveryError::Permanent(reason)) => return Outcome::Dropped(reason),
					};
					let auth = match (&rule.username, &rule.password) {
						(Some(user), Some(pass)) => Some((user.clone(), pass.clone())),
						_ => None,
					};
					// starttls (required whenever AUTH is configured) forces TLS.
					// DANE does not apply to a configured smarthost (RFC 7672 is
					// keyed on the recipient's MX), so no TLSA records here.
					(stream, host, auth, rule.starttls, Vec::new())
				}
				_ => {
					// Direct (no rule, or kind = direct): MX delivery.
					match self.connector.connect(&domain, policy.as_ref()).await {
						Ok((stream, server_name)) => {
							// DANE: TLSA is published under the MX hostname. A
							// transient TLSA lookup failure defers delivery rather
							// than downgrading to opportunistic TLS (RFC 7672 §2.1).
							let tlsa = match self.tlsa_for(&server_name).await {
								Ok(records) => records,
								Err(crate::spf::DnsFailure::Temporary) => {
									return Outcome::Retry(format!(
										"transient TLSA lookup failure for {server_name}"
									));
								}
							};
							(stream, server_name, None, require_tls, tlsa)
						}
						Err(DeliveryError::Transient(reason)) => return Outcome::Retry(reason),
						Err(DeliveryError::Permanent(reason)) => return Outcome::Dropped(reason),
					}
				}
			};
			let result = client::deliver(
				stream,
				&server_name,
				&self.ehlo_hostname,
				&entry.envelope.reverse_path,
				&recipients,
				&entry.data,
				tls_required,
				auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
				&dane,
			)
			.await;
			match result {
				Ok(()) => {}
				Err(DeliveryError::Transient(reason)) => return Outcome::Retry(reason),
				Err(DeliveryError::Permanent(reason)) => return Outcome::Dropped(reason),
			}
		}
		Outcome::Delivered
	}
}

enum Outcome {
	Delivered,
	Retry(String),
	Dropped(String),
	/// Every recipient is suppressed; drop without bouncing.
	Suppressed,
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
