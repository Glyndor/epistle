//! The queue worker: drains the outbound spool.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::smtp::sink::MessageSink;
use crate::storage::{FsSpool, RecipientStatus, SpoolEntry};

use super::client::DeliveryError;
use super::resolver::Connector;
use conversation::Conversation;

#[path = "worker_attempt.rs"]
mod attempt;
#[path = "worker_claims.rs"]
mod claims;
#[path = "worker_conversation.rs"]
mod conversation;
#[path = "worker_evidence.rs"]
mod evidence;
#[path = "worker_reports.rs"]
mod reports;
#[path = "worker_scheduler.rs"]
mod scheduler;
#[path = "worker_waiting.rs"]
mod waiting;
#[path = "worker_warmup.rs"]
mod warmup;

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
	/// Per-recipient delivery log. `None` when the operator turned it off
	/// (`[storage] delivery_log_days = 0`); the writer is then a no-op
	/// and no records are produced.
	delivery_log: Option<crate::storage::DeliveryLog>,
	/// Records the outcomes of messages that keep evidence.
	evidence: Option<Arc<crate::evidence::service::EvidenceService>>,
	/// How many conversations run at once, overall and per domain.
	limits: super::limits::Limits,
	/// Recipients in conversation, and the slots in use.
	claims: claims::Claims,
	/// Held while an entry is settled, so two passes never send the same
	/// failure report twice.
	settling: std::sync::Mutex<()>,
	/// How long a destination that asks to slow down is held off, by the
	/// number of times in a row it did (seconds).
	backoff_steps: Vec<u64>,
	/// The longest one delivery attempt to one domain may take.
	attempt_limit: Duration,
	/// The destinations on hold, as the spool shows them: rebuilt from the
	/// spool at every scan and kept in step with what this worker writes
	/// there, so it never allows what the spool would defer.
	holds: std::sync::Mutex<super::backoff::Holds>,
	/// The IP warm-up, when one applies: recipients over the daily cap of
	/// their receiver group wait for it.
	warmup: Option<Arc<super::warmup::Warmup>>,
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
			delivery_log: None,
			evidence: None,
			limits: super::limits::Limits::default(),
			claims: claims::Claims::default(),
			settling: std::sync::Mutex::new(()),
			backoff_steps: super::backoff::DEFAULT_STEPS.to_vec(),
			attempt_limit: super::timeouts::ATTEMPT,
			holds: Default::default(),
			warmup: None,
		}
	}

	/// Hold off a destination that asks to slow down for these waits
	/// (seconds), one per deferral in a row, the last repeating. Empty keeps
	/// the default.
	pub fn with_backoff(mut self, steps: Vec<u64>) -> Self {
		if !steps.is_empty() {
			self.backoff_steps = steps;
		}
		self
	}

	/// Run up to `total` conversations at once, and up to `per_domain` of
	/// them with any one recipient domain. Zero keeps the default.
	pub fn with_concurrency(mut self, total: usize, per_domain: usize) -> Self {
		self.limits = super::limits::Limits::new(total, per_domain);
		self
	}

	/// Enable the per-recipient delivery log. A `0`-retention `log` is
	/// a no-op; the worker still takes it so the same wiring runs
	/// regardless of configuration.
	pub fn with_delivery_log(mut self, log: crate::storage::DeliveryLog) -> Self {
		self.delivery_log = Some(log);
		self
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

	/// The TLSA RRset of an MX host, queried at `_25._tcp.<host>` (RFC 7672
	/// §3). `Absent` when DANE is disabled, the host publishes none, or the
	/// response is not authenticated: only validated records ever count.
	///
	/// A transient TLSA lookup failure is propagated as `Err`, never collapsed
	/// into an empty result: treating a temporary resolver error as "no DANE"
	/// would silently downgrade a host that does publish TLSA, defeating the
	/// downgrade protection DANE exists for (RFC 7672 §2.1). The caller defers
	/// delivery in that case instead.
	async fn tlsa_for(
		&self,
		mx_host: &str,
	) -> Result<crate::dane::rrset::TlsaRrset, crate::spf::DnsFailure> {
		match &self.dane_dns {
			Some(dns) => dns.tlsa(&format!("_25._tcp.{mx_host}")).await,
			None => Ok(crate::dane::rrset::TlsaRrset::Absent),
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
	fn set_attempt_limit(&mut self, limit: Duration) {
		self.attempt_limit = limit;
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

	/// Run forever: scan the spool every `interval`, and start waiting
	/// conversations as soon as running ones end, so a slow destination
	/// never holds up the next scan.
	pub async fn run(self: Arc<Self>, interval: Duration) {
		let worker: &Worker = &self;
		let mut ticks = tokio::time::interval(interval);
		ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		let mut schedule = scheduler::Schedule::default();
		loop {
			let done = tokio::select! {
				_ = ticks.tick() => None,
				done = scheduler::next_done(schedule.running_mut()), if !schedule.is_idle() => done,
			};
			match done {
				Some(done) => worker.complete(&mut schedule, done),
				None => {
					if let Err(error) = worker.scan(&mut schedule) {
						tracing::warn!(%error, "queue scan failed");
					}
				}
			}
			worker.fill(&mut schedule);
			if let Some(error) = schedule.error.take() {
				tracing::warn!(%error, "queue pass failed");
			}
		}
	}

	/// One pass over the spool: every due recipient is attempted, in
	/// conversations that run side by side within the caps, and the pass
	/// returns once they have all ended. Returns the number of entries that
	/// had at least one recipient delivered in this pass.
	pub async fn pass(&self) -> std::io::Result<usize> {
		self.write_waiting_outcomes();
		let mut schedule = scheduler::Schedule::default();
		self.scan(&mut schedule)?;
		self.drain(&mut schedule).await;
		match schedule.error.take() {
			Some(error) => Err(error),
			None => Ok(schedule.delivered),
		}
	}

	/// The destinations on hold.
	fn holds(&self) -> std::sync::MutexGuard<'_, super::backoff::Holds> {
		self.holds
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Write one conversation's outcome to the envelope, then act on it.
	fn record(
		&self,
		id: uuid::Uuid,
		entry: &SpoolEntry,
		conversation: &Conversation,
		now: u64,
	) -> std::io::Result<()> {
		let retry_now = conversation.retry_now();
		let slow = self.slow_down(entry, conversation, now);
		self.spool.update_envelope(id, |envelope| {
			for (recipient, result) in &conversation.results {
				let mut state = envelope.recipient_state(recipient);
				if let Some(capped) = conversation.capped_for(recipient) {
					// Over the warm-up cap: not attempted, so nothing of
					// the attempt is written.
					state.wait_for_cap(capped.group.label(), capped.until, now);
					envelope.set_recipient_state(recipient, state);
					continue;
				}
				state.end_cap_wait(now);
				state.remote = conversation.remote.clone();
				match result {
					// Left for another transaction: due again now, and not
					// an attempt that failed.
					Err(_) if retry_now.contains(recipient) => state.next_attempt = now,
					// Every exchanger reached was on hold: nothing was
					// attempted, and the recipient waits for the hold.
					Err(DeliveryError::Transient(reason)) if conversation.held_until.is_some() => {
						state.next_attempt = conversation.held_until.unwrap_or(now);
						state.last_error = Some(reason.clone());
					}
					Ok(()) => state.status = RecipientStatus::Delivered,
					Err(DeliveryError::Transient(reason)) => {
						if reports::logs_deferral(&state, reason) {
							// Counted here, where the state is written; the
							// record itself is written once the outcome is.
							state.deferrals_logged += 1;
						}
						state.attempts += 1;
						state.next_attempt = self.retry_at(now, state.attempts);
						state.last_error = Some(reason.clone());
						state.throttled = 0;
						if let Some(slow) = &slow {
							// The destination asked to slow down: wait for
							// the next step of the backoff, and no longer.
							// The recipient's wait is the hold of the whole
							// destination, so a recipient far into its own
							// retry schedule must not hold every other
							// message to it for that long.
							state.next_attempt = slow.until;
							state.throttled = slow.deferrals;
							state.last_error = Some(slow.reason.clone());
							state.remote = slow.host.clone().or(state.remote);
						}
						envelope.last_error = state
							.last_error
							.as_ref()
							.map(|reason| reason.chars().take(512).collect());
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
		if let Some(slow) = slow {
			let mut holds = self.holds();
			holds.note(slow.domain, slow.until, slow.deferrals, &slow.reason);
			if let Some(host) = &slow.host {
				holds.note(
					super::destination::Destination::exchanger(host),
					slow.until,
					slow.deferrals,
					&slow.reason,
				);
			}
		}
		self.after_conversation(id, entry, conversation);
		Ok(())
	}

	/// Settle an entry after its conversations: expire it when too old, send
	/// the failure report for recipients that failed, warn about a long
	/// delay, and remove it once no recipient is pending.
	///
	/// Recipients another conversation holds right now are left alone: they
	/// are neither expired nor reported until that conversation ends.
	fn finish(&self, id: uuid::Uuid, now: u64, delivered: bool) -> std::io::Result<()> {
		let _settling = self
			.settling
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let envelope = self.spool.load_envelope(id)?;
		// Give up by message age, not attempt count: a recipient down for
		// hours must not lose mail (RFC 5321 §4.5.4.1). The time an operator
		// held the message and the time a recipient waited for the warm-up
		// cap are not part of that age.
		let expired: Vec<String> = envelope
			.pending()
			.into_iter()
			.filter(|recipient| !self.claims.holds(id, recipient))
			.filter(|recipient| {
				self.window_used(id, &envelope, recipient, now) >= self.max_age_secs
			})
			.collect();
		if !expired.is_empty() {
			self.expire(id, &expired)?;
		}
		if delivered {
			self.metric(|m| m.relayed());
		}
		if self.report_failures(id)? {
			self.metric(|m| m.bounced());
		}
		let envelope = self.spool.load_envelope(id)?;
		let pending = envelope.pending();
		if pending.is_empty() {
			// An outcome the log has not taken keeps the entry: it is
			// removed when the outcome is written.
			return match envelope.outcomes_pending.is_empty() {
				true => self.spool.remove(id),
				false => Ok(()),
			};
		}
		let age = pending
			.iter()
			.map(|recipient| self.window_used(id, &envelope, recipient, now))
			.max()
			.unwrap_or(0);
		if age >= self.schedule.delay_warning {
			self.warn_delayed(id);
		}
		let capped = pending
			.iter()
			.all(|recipient| envelope.recipient_state(recipient).warmup.is_some());
		if !capped {
			// Waiting for the warm-up cap is not a deferral.
			tracing::debug!(%id, age, "delivery deferred");
			self.metric(|m| m.deferred());
		}
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
#[path = "worker_tests_policy_matrix.rs"]
mod tests_policy_matrix;

#[cfg(test)]
#[path = "worker_tests_tls_required.rs"]
mod tests_tls_required;

#[cfg(test)]
#[path = "worker_tests_sts_discovery.rs"]
mod tests_sts_discovery;

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

#[cfg(test)]
#[path = "worker_tests_evidence.rs"]
mod tests_evidence;

#[cfg(test)]
#[path = "worker_tests_delivery_log.rs"]
mod tests_delivery_log;

#[cfg(test)]
#[path = "worker_tests_parallel.rs"]
mod tests_parallel;

#[cfg(test)]
#[path = "worker_tests_backoff.rs"]
mod tests_backoff;

#[cfg(test)]
#[path = "worker_tests_next_mx.rs"]
mod tests_next_mx;

#[cfg(test)]
#[path = "worker_tests_provider.rs"]
mod tests_provider;

#[cfg(test)]
#[path = "worker_tests_recipient_kinds.rs"]
mod tests_recipient_kinds;

#[cfg(test)]
#[path = "worker_tests_fairness.rs"]
mod tests_fairness;

#[cfg(test)]
#[path = "worker_tests_spool_holds.rs"]
mod tests_spool_holds;

#[cfg(test)]
#[path = "worker_tests_scan.rs"]
mod tests_scan;
