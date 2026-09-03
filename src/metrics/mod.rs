//! Server-side metrics in Prometheus text format.
//!
//! The mail server owns the counters and exposes them; dashboards live in the
//! admin panel. Counters are process-global atomics, cheap to bump on the hot
//! path, and rendered on demand for the `/metrics` endpoint.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Why an inbound message was rejected, for the per-reason counter label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
	/// Rejected because the client IP appeared in a configured DNSBL.
	Dnsbl,
	/// Rejected because SPF did not pass and the receiver's policy enforces.
	Spf,
	/// Rejected because DMARC alignment failed and the record's policy is
	/// `reject` (or `quarantine`, which the metrics treat as a rejection).
	Dmarc,
	/// Rejected because the sender's reputation crossed the suspect
	/// threshold.
	Reputation,
	/// Rejected by an external content scanner (ClamAV/Rspamd).
	Scanner,
	/// Rejected because the message was a loop (our own envelope sender on
	/// a received message, e.g. via SRS / an alias chain).
	Loop,
	/// Rejected at `MAIL FROM` because the unauthenticated client tripped
	/// the configured per-IP or per-sender rate limit. The reply is `450`,
	/// so the rejection is temporary and the peer is expected to retry.
	RateLimit,
}

impl RejectReason {
	fn label(self) -> &'static str {
		match self {
			RejectReason::Dnsbl => "dnsbl",
			RejectReason::Spf => "spf",
			RejectReason::Dmarc => "dmarc",
			RejectReason::Reputation => "reputation",
			RejectReason::Scanner => "scanner",
			RejectReason::Loop => "loop",
			RejectReason::RateLimit => "rate_limit",
		}
	}
}

const REASONS: [RejectReason; 7] = [
	RejectReason::Dnsbl,
	RejectReason::Spf,
	RejectReason::Dmarc,
	RejectReason::Reputation,
	RejectReason::Scanner,
	RejectReason::Loop,
	RejectReason::RateLimit,
];

/// Canonical short names of every counter, paired with the matching field.
///
/// Used by [`Metrics::snapshot`] to enumerate the counters and by the config
/// validator to reject unknown `[[alerts]] metric = "..."` values with the
/// full list of valid names in the error message.
const COUNTERS: &[(&str, &str)] = &[
	("connections", "connections"),
	("accepted", "accepted"),
	("quarantined", "quarantined"),
	("rejected_dnsbl", "rejected_dnsbl"),
	("rejected_spf", "rejected_spf"),
	("rejected_dmarc", "rejected_dmarc"),
	("rejected_reputation", "rejected_reputation"),
	("rejected_scanner", "rejected_scanner"),
	("rejected_loop", "rejected_loop"),
	("rejected_rate_limit", "rejected_rate_limit"),
	("abuse_dropped", "abuse_dropped"),
	("sieve_rejected", "sieve_rejected"),
	("vacation_sent", "vacation_sent"),
	("forwarded", "forwarded"),
	("relayed", "relayed"),
	("deferred", "deferred"),
	("bounced", "bounced"),
	("webhook_sent", "webhook_sent"),
	("webhook_failed", "webhook_failed"),
	("database_unavailable", "database_unavailable"),
	("clock_drift_exceeded", "clock_drift_exceeded"),
	("auth_login_succeeded", "auth_login_succeeded"),
	("auth_login_failed", "auth_login_failed"),
];

/// Canonical short names of every counter, sorted.
///
/// The alert engine validates `[[alerts]] metric` against this list; the
/// validator reports the names from here when rejecting an unknown metric.
pub fn metric_names() -> Vec<&'static str> {
	COUNTERS.iter().map(|(name, _)| *name).collect()
}

/// Process-global mail metrics.
#[derive(Debug, Default)]
pub struct Metrics {
	connections: AtomicU64,
	accepted: AtomicU64,
	quarantined: AtomicU64,
	rejected_dnsbl: AtomicU64,
	rejected_spf: AtomicU64,
	rejected_dmarc: AtomicU64,
	rejected_reputation: AtomicU64,
	rejected_scanner: AtomicU64,
	rejected_loop: AtomicU64,
	rejected_rate_limit: AtomicU64,
	abuse_dropped: AtomicU64,
	sieve_rejected: AtomicU64,
	vacation_sent: AtomicU64,
	forwarded: AtomicU64,
	relayed: AtomicU64,
	deferred: AtomicU64,
	bounced: AtomicU64,
	webhook_sent: AtomicU64,
	webhook_failed: AtomicU64,
	database_unavailable: AtomicU64,
	clock_drift_exceeded: AtomicU64,
	auth_login_succeeded: AtomicU64,
	auth_login_failed: AtomicU64,
	llm_consulted: AtomicU64,
	llm_quarantined: AtomicU64,
	llm_failed: AtomicU64,
}

impl Metrics {
	/// An empty metrics struct, with every counter at zero.
	pub fn new() -> Self {
		Self::default()
	}

	/// Count a connection dropped by the error-streak abuse guard.
	pub fn abuse_dropped(&self) {
		self.abuse_dropped.fetch_add(1, Ordering::Relaxed);
	}

	/// Count an accepted inbound SMTP connection.
	pub fn connection(&self) {
		self.connections.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a delivered message.
	pub fn accepted(&self) {
		self.accepted.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message quarantined to Rejects.
	pub fn quarantined(&self) {
		self.quarantined.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message refused by a Sieve `reject`/`ereject`.
	pub fn sieve_rejected(&self) {
		self.sieve_rejected.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a Sieve `vacation` autoresponse sent.
	pub fn vacation_sent(&self) {
		self.vacation_sent.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message forwarded by a Sieve `redirect`.
	pub fn forwarded(&self) {
		self.forwarded.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message relayed to a remote server by the outbound queue.
	pub fn relayed(&self) {
		self.relayed.fetch_add(1, Ordering::Relaxed);
	}

	/// Count an outbound delivery deferred for later retry.
	pub fn deferred(&self) {
		self.deferred.fetch_add(1, Ordering::Relaxed);
	}

	/// Count an outbound message bounced (permanently undeliverable).
	pub fn bounced(&self) {
		self.bounced.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a webhook event delivered successfully.
	pub fn webhook_sent(&self) {
		self.webhook_sent.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a webhook event that failed to deliver (advisory; mail unaffected).
	pub fn webhook_failed(&self) {
		self.webhook_failed.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a startup that could not reach the configured database and carried
	/// on without the antispam engine (advisory; mail keeps flowing, unfiltered).
	pub fn database_unavailable(&self) {
		self.database_unavailable.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a startup whose clock-drift probe observed a wall-clock jump
	/// larger than the threshold tied to the TOTP acceptance window. The
	/// counter is what the alert engine reads; a one-shot `warn!` at the
	/// probe site is the human-readable companion.
	pub fn clock_drift_exceeded(&self) {
		self.clock_drift_exceeded.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a password-based authentication attempt that resolved an
	/// account (PLAIN/LOGIN/IMAP LOGIN/WebDAV Basic/ManageSieve/API verify).
	pub fn auth_login_succeeded(&self) {
		self.auth_login_succeeded.fetch_add(1, Ordering::Relaxed);
	}

	/// Count the same surface that was rejected: unknown account, disabled
	/// account, wrong password, app-password CIDR rejection, or an LDAP
	/// bind failure.
	pub fn auth_login_failed(&self) {
		self.auth_login_failed.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message sent to the LLM antispam hook for a second opinion.
	/// Only incremented when the local Bayesian score sits inside the
	/// configured uncertain band, so it measures the real cost of the feature.
	pub fn llm_consulted(&self) {
		self.llm_consulted.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message the LLM hook quarantined (spam with high confidence).
	pub fn llm_quarantined(&self) {
		self.llm_quarantined.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message the LLM hook could not classify (transport, timeout,
	/// parse or shape failure). Fail-open: the message is still accepted.
	pub fn llm_failed(&self) {
		self.llm_failed.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a rejected message by reason.
	pub fn rejected(&self, reason: RejectReason) {
		self.counter(reason).fetch_add(1, Ordering::Relaxed);
	}

	fn counter(&self, reason: RejectReason) -> &AtomicU64 {
		match reason {
			RejectReason::Dnsbl => &self.rejected_dnsbl,
			RejectReason::Spf => &self.rejected_spf,
			RejectReason::Dmarc => &self.rejected_dmarc,
			RejectReason::Reputation => &self.rejected_reputation,
			RejectReason::Scanner => &self.rejected_scanner,
			RejectReason::Loop => &self.rejected_loop,
			RejectReason::RateLimit => &self.rejected_rate_limit,
		}
	}

	/// Snapshot every counter by its short name.
	///
	/// The keys are the names the alert engine accepts in `[[alerts]] metric`
	/// and are stable across releases: they are the canonical short identifiers
	/// of each counter, distinct from the Prometheus exposition names (which
	/// carry a `mail_` prefix and `_total` suffix).
	pub fn snapshot(&self) -> BTreeMap<&'static str, u64> {
		let mut map = BTreeMap::new();
		for (name, field) in COUNTERS {
			map.insert(*name, self.counter_by_field(field).load(Ordering::Relaxed));
		}
		map
	}

	fn counter_by_field(&self, field: &str) -> &AtomicU64 {
		match field {
			"connections" => &self.connections,
			"accepted" => &self.accepted,
			"quarantined" => &self.quarantined,
			"rejected_dnsbl" => &self.rejected_dnsbl,
			"rejected_spf" => &self.rejected_spf,
			"rejected_dmarc" => &self.rejected_dmarc,
			"rejected_reputation" => &self.rejected_reputation,
			"rejected_scanner" => &self.rejected_scanner,
			"rejected_loop" => &self.rejected_loop,
			"rejected_rate_limit" => &self.rejected_rate_limit,
			"abuse_dropped" => &self.abuse_dropped,
			"sieve_rejected" => &self.sieve_rejected,
			"vacation_sent" => &self.vacation_sent,
			"forwarded" => &self.forwarded,
			"relayed" => &self.relayed,
			"deferred" => &self.deferred,
			"bounced" => &self.bounced,
			"webhook_sent" => &self.webhook_sent,
			"webhook_failed" => &self.webhook_failed,
			"database_unavailable" => &self.database_unavailable,
			"clock_drift_exceeded" => &self.clock_drift_exceeded,
			"auth_login_succeeded" => &self.auth_login_succeeded,
			"auth_login_failed" => &self.auth_login_failed,
			other => unreachable!("unknown counter field {other}"),
		}
	}

	/// Render all counters in Prometheus text exposition format.
	pub fn render(&self) -> String {
		let mut out = String::new();
		out.push_str("# HELP mail_connections_total Accepted SMTP connections.\n");
		out.push_str("# TYPE mail_connections_total counter\n");
		out.push_str(&format!(
			"mail_connections_total {}\n",
			self.connections.load(Ordering::Relaxed)
		));

		out.push_str("# HELP mail_messages_accepted_total Delivered inbound messages.\n");
		out.push_str("# TYPE mail_messages_accepted_total counter\n");
		out.push_str(&format!(
			"mail_messages_accepted_total {}\n",
			self.accepted.load(Ordering::Relaxed)
		));

		out.push_str("# HELP mail_messages_quarantined_total Messages filed to Rejects.\n");
		out.push_str("# TYPE mail_messages_quarantined_total counter\n");
		out.push_str(&format!(
			"mail_messages_quarantined_total {}\n",
			self.quarantined.load(Ordering::Relaxed)
		));

		out.push_str("# HELP mail_messages_rejected_total Rejected inbound messages by reason.\n");
		out.push_str("# TYPE mail_messages_rejected_total counter\n");
		for reason in REASONS {
			out.push_str(&format!(
				"mail_messages_rejected_total{{reason=\"{}\"}} {}\n",
				reason.label(),
				self.counter(reason).load(Ordering::Relaxed)
			));
		}

		out.push_str(
			"# HELP mail_connections_abuse_dropped_total Connections dropped for too many errors.\n",
		);
		out.push_str("# TYPE mail_connections_abuse_dropped_total counter\n");
		out.push_str(&format!(
			"mail_connections_abuse_dropped_total {}\n",
			self.abuse_dropped.load(Ordering::Relaxed)
		));

		for (name, help, counter) in [
			(
				"mail_sieve_rejected_total",
				"Messages refused by a Sieve reject.",
				&self.sieve_rejected,
			),
			(
				"mail_vacation_sent_total",
				"Sieve vacation autoresponses sent.",
				&self.vacation_sent,
			),
			(
				"mail_forwarded_total",
				"Messages forwarded by a Sieve redirect.",
				&self.forwarded,
			),
			(
				"mail_relayed_total",
				"Messages relayed to remote servers.",
				&self.relayed,
			),
			(
				"mail_deferred_total",
				"Outbound deliveries deferred for retry.",
				&self.deferred,
			),
			(
				"mail_bounced_total",
				"Outbound messages permanently bounced.",
				&self.bounced,
			),
			(
				"mail_webhook_sent_total",
				"Webhook events delivered successfully.",
				&self.webhook_sent,
			),
			(
				"mail_webhook_failed_total",
				"Webhook events that failed to deliver.",
				&self.webhook_failed,
			),
			(
				"mail_database_unavailable_total",
				"Startups that could not reach the database and ran without the antispam engine.",
				&self.database_unavailable,
			),
			(
				"mail_clock_drift_exceeded_total",
				"Startups whose clock-drift probe observed a wall-clock jump past the TOTP acceptance window.",
				&self.clock_drift_exceeded,
			),
			(
				"mail_auth_login_succeeded_total",
				"Password-based authentication attempts that resolved an account.",
				&self.auth_login_succeeded,
			),
			(
				"mail_auth_login_failed_total",
				"Password-based authentication attempts that were rejected.",
				&self.auth_login_failed,
			),
			(
				"mail_llm_consulted_total",
				"Messages sent to the LLM antispam hook (uncertain band only).",
				&self.llm_consulted,
			),
			(
				"mail_llm_quarantined_total",
				"Messages quarantined after the LLM antispam hook answered spam.",
				&self.llm_quarantined,
			),
			(
				"mail_llm_failed_total",
				"LLM antispam hook calls that failed (the message was accepted).",
				&self.llm_failed,
			),
		] {
			out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
			out.push_str(&format!("{name} {}\n", counter.load(Ordering::Relaxed)));
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn renders_zero_counters() {
		let rendered = Metrics::new().render();
		assert!(rendered.contains("mail_connections_total 0\n"));
		assert!(rendered.contains("mail_messages_rejected_total{reason=\"dnsbl\"} 0\n"));
		// Every reason label is present.
		for label in [
			"dnsbl",
			"spf",
			"dmarc",
			"reputation",
			"scanner",
			"loop",
			"rate_limit",
		] {
			assert!(rendered.contains(&format!("reason=\"{label}\"")), "{label}");
		}
	}

	#[test]
	fn counts_events() {
		let m = Metrics::new();
		m.connection();
		m.connection();
		m.accepted();
		m.quarantined();
		m.rejected(RejectReason::Dnsbl);
		m.rejected(RejectReason::Dnsbl);
		m.rejected(RejectReason::Dmarc);
		m.abuse_dropped();
		m.sieve_rejected();
		m.vacation_sent();
		m.vacation_sent();
		m.forwarded();
		m.relayed();
		m.relayed();
		m.relayed();
		m.deferred();
		m.bounced();
		m.auth_login_succeeded();
		m.auth_login_succeeded();
		m.auth_login_failed();
		m.llm_consulted();
		m.llm_consulted();
		m.llm_quarantined();
		m.llm_failed();
		let r = m.render();
		assert!(r.contains("mail_sieve_rejected_total 1\n"), "{r}");
		assert!(r.contains("mail_vacation_sent_total 2\n"), "{r}");
		assert!(r.contains("mail_forwarded_total 1\n"), "{r}");
		assert!(r.contains("mail_relayed_total 3\n"), "{r}");
		assert!(r.contains("mail_deferred_total 1\n"), "{r}");
		assert!(r.contains("mail_bounced_total 1\n"), "{r}");
		assert!(r.contains("mail_connections_total 2\n"), "{r}");
		assert!(
			r.contains("mail_connections_abuse_dropped_total 1\n"),
			"{r}"
		);
		assert!(r.contains("mail_messages_accepted_total 1\n"), "{r}");
		assert!(r.contains("mail_messages_quarantined_total 1\n"), "{r}");
		assert!(r.contains("mail_auth_login_succeeded_total 2\n"), "{r}");
		assert!(r.contains("mail_auth_login_failed_total 1\n"), "{r}");
		assert!(r.contains("mail_llm_consulted_total 2\n"), "{r}");
		assert!(r.contains("mail_llm_quarantined_total 1\n"), "{r}");
		assert!(r.contains("mail_llm_failed_total 1\n"), "{r}");
		assert!(
			r.contains("mail_messages_rejected_total{reason=\"dnsbl\"} 2\n"),
			"{r}"
		);
		assert!(
			r.contains("mail_messages_rejected_total{reason=\"dmarc\"} 1\n"),
			"{r}"
		);
	}

	#[test]
	fn render_is_valid_exposition_with_help_and_type() {
		let r = Metrics::new().render();
		assert!(r.contains("# TYPE mail_connections_total counter"));
		assert!(r.contains("# HELP mail_messages_accepted_total"));
	}

	#[test]
	fn snapshot_lists_every_counter_and_keeps_it_sorted() {
		let m = Metrics::new();
		m.connection();
		m.connection();
		m.accepted();
		m.bounced();
		m.bounced();
		m.bounced();
		let snap = m.snapshot();
		assert_eq!(snap.get("connections"), Some(&2));
		assert_eq!(snap.get("accepted"), Some(&1));
		assert_eq!(snap.get("bounced"), Some(&3));
		// Sorted alphabetically.
		let keys: Vec<&str> = snap.keys().copied().collect();
		let mut sorted = keys.clone();
		sorted.sort_unstable();
		assert_eq!(keys, sorted);
		// Every counter the alert engine accepts is present at zero.
		for name in [
			"connections",
			"accepted",
			"quarantined",
			"rejected_dnsbl",
			"rejected_spf",
			"rejected_dmarc",
			"rejected_reputation",
			"rejected_scanner",
			"rejected_loop",
			"rejected_rate_limit",
			"abuse_dropped",
			"sieve_rejected",
			"vacation_sent",
			"forwarded",
			"relayed",
			"deferred",
			"bounced",
			"webhook_sent",
			"webhook_failed",
			"database_unavailable",
			"clock_drift_exceeded",
			"auth_login_succeeded",
			"auth_login_failed",
		] {
			assert!(snap.contains_key(name), "missing {name}");
		}
	}
}
