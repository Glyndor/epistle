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
	/// Rejected because the message has more header fields than a Sieve
	/// filter reads (`554 5.6.0`).
	HeaderFields,
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
			RejectReason::HeaderFields => "header_fields",
		}
	}
}

const REASONS: [RejectReason; 8] = [
	RejectReason::Dnsbl,
	RejectReason::Spf,
	RejectReason::Dmarc,
	RejectReason::Reputation,
	RejectReason::Scanner,
	RejectReason::Loop,
	RejectReason::RateLimit,
	RejectReason::HeaderFields,
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
	("rejected_header_fields", "rejected_header_fields"),
	("abuse_dropped", "abuse_dropped"),
	("sieve_rejected", "sieve_rejected"),
	("sieve_inspection_truncated", "sieve_inspection_truncated"),
	("vacation_sent", "vacation_sent"),
	("forwarded", "forwarded"),
	("relayed", "relayed"),
	("deferred", "deferred"),
	("bounced", "bounced"),
	("outbound_policy_rejected", "outbound_policy_rejected"),
	("webhook_sent", "webhook_sent"),
	("webhook_failed", "webhook_failed"),
	("scanner_clamd_failed", "scanner_clamd_failed"),
	("scanner_clamd_skipped", "scanner_clamd_skipped"),
	("outbound_virus", "outbound_virus"),
	("database_unavailable", "database_unavailable"),
	("clock_drift_exceeded", "clock_drift_exceeded"),
	("auth_login_succeeded", "auth_login_succeeded"),
	("auth_login_failed", "auth_login_failed"),
	("send_limited_new_recipients", "send_limited_new_recipients"),
	("bayes_training_dropped", "bayes_training_dropped"),
	("subjectpass_passed", "subjectpass_passed"),
	("subjectpass_challenged", "subjectpass_challenged"),
	("dmarc_reports_ingested", "dmarc_reports_ingested"),
	("dmarc_report_rows_failing", "dmarc_report_rows_failing"),
	("tlsrpt_reports_ingested", "tlsrpt_reports_ingested"),
	("tlsrpt_failed_sessions", "tlsrpt_failed_sessions"),
	("reports_dropped", "reports_dropped"),
	("mta_sts_connections_dropped", "mta_sts_connections_dropped"),
	("accept_failed", "accept_failed"),
	("warmup_held", "warmup_held"),
	("warmup_backoff", "warmup_backoff"),
];

/// Failed accepts on any listener. Process-wide rather than per
/// [`Metrics`] so every accept loop counts here without carrying a handle.
static ACCEPT_FAILED: AtomicU64 = AtomicU64::new(0);

/// Count a failed `accept` on any listener.
pub fn accept_failed() {
	ACCEPT_FAILED.fetch_add(1, Ordering::Relaxed);
}

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
	rejected_header_fields: AtomicU64,
	abuse_dropped: AtomicU64,
	sieve_rejected: AtomicU64,
	sieve_inspection_truncated: AtomicU64,
	vacation_sent: AtomicU64,
	forwarded: AtomicU64,
	relayed: AtomicU64,
	deferred: AtomicU64,
	bounced: AtomicU64,
	outbound_policy_rejected: AtomicU64,
	webhook_sent: AtomicU64,
	webhook_failed: AtomicU64,
	scanner_clamd_failed: AtomicU64,
	scanner_clamd_skipped: AtomicU64,
	outbound_virus: AtomicU64,
	database_unavailable: AtomicU64,
	clock_drift_exceeded: AtomicU64,
	auth_login_succeeded: AtomicU64,
	auth_login_failed: AtomicU64,
	send_limited_new_recipients: AtomicU64,
	bayes_training_dropped: AtomicU64,
	dmarc_reports_ingested: AtomicU64,
	dmarc_report_rows_failing: AtomicU64,
	tlsrpt_reports_ingested: AtomicU64,
	tlsrpt_failed_sessions: AtomicU64,
	reports_dropped: AtomicU64,
	mta_sts_connections_dropped: AtomicU64,
	llm_consulted: AtomicU64,
	llm_quarantined: AtomicU64,
	llm_failed: AtomicU64,
	subjectpass_passed: AtomicU64,
	subjectpass_challenged: AtomicU64,
	warmup_held: AtomicU64,
	warmup_backoff: AtomicU64,
}

impl Metrics {
	/// An empty metrics struct, with every counter at zero.
	pub fn new() -> Self {
		Self::default()
	}

	/// Count a clamd exchange failure that accepted the message.
	pub fn scanner_clamd_failed(&self) {
		self.scanner_clamd_failed.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a message skipped because it exceeded the clamd byte limit.
	pub fn scanner_clamd_skipped(&self) {
		self.scanner_clamd_skipped.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a submission the antivirus refused: an account sent malware.
	pub fn outbound_virus(&self) {
		self.outbound_virus.fetch_add(1, Ordering::Relaxed);
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

	/// Count a message a Sieve test could not look at whole (a body past its
	/// window, more headers of a name than a lookup visits).
	pub fn sieve_inspection_truncated(&self) {
		self.sieve_inspection_truncated
			.fetch_add(1, Ordering::Relaxed);
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

	/// Count an outbound recipient a remote refused on policy grounds
	/// (RFC 3463 5.7.x): a sign of a sending-reputation or authentication
	/// problem, not of a bad address.
	pub fn outbound_policy_rejected(&self) {
		self.outbound_policy_rejected
			.fetch_add(1, Ordering::Relaxed);
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

	/// Count a submission refused because the account would exceed the
	/// rolling 24h cap on first-time recipients (`Config::new_recipients_per_day`).
	/// Distinct from the per-minute `submission_rate_limit_per_min`:
	/// that limiter sees volume, this one sees *novel* addresses, which
	/// is the slow-exfiltration signal.
	pub fn send_limited_new_recipients(&self) {
		self.send_limited_new_recipients
			.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a per-account Bayesian training job dropped because the
	/// bounded queue that hands work from STORE / `Email/set` to the
	/// one training worker was full. The queue is advisory and never
	/// blocks the protocol reply, so a non-zero counter means the
	/// worker cannot keep up with the rate of `$Junk` flag flips and
	/// the operator should widen the queue or scale training.
	pub fn bayes_training_dropped(&self) {
		self.bayes_training_dropped.fetch_add(1, Ordering::Relaxed);
	}

	/// Count `jobs` lessons dropped at once.
	pub fn bayes_training_dropped_by(&self, jobs: u64) {
		self.bayes_training_dropped
			.fetch_add(jobs, Ordering::Relaxed);
	}

	/// Count one ingested DMARC aggregate or TLS-RPT report.
	pub fn report_ingested(&self, kind: crate::reports::Kind) {
		let counter = match kind {
			crate::reports::Kind::Dmarc => &self.dmarc_reports_ingested,
			crate::reports::Kind::TlsRpt => &self.tlsrpt_reports_ingested,
		};
		counter.fetch_add(1, Ordering::Relaxed);
	}

	/// Sum the failing rows from an ingested report (DMARC rows whose
	/// disposition is `quarantine`/`reject`, or with both dkim and spf
	/// `fail`; for TLS-RPT, the `total-failure-session-count` from each
	/// policy).
	pub fn report_rows_failing(&self, kind: crate::reports::Kind, count: u64) {
		let counter = match kind {
			crate::reports::Kind::Dmarc => &self.dmarc_report_rows_failing,
			crate::reports::Kind::TlsRpt => &self.tlsrpt_failed_sessions,
		};
		counter.fetch_add(count, Ordering::Relaxed);
	}

	/// Count an IP warm-up day that went badly for a receiver group: the
	/// group's cap held.
	pub fn warmup_held(&self) {
		self.warmup_held.fetch_add(1, Ordering::Relaxed);
	}

	/// Count an IP warm-up day that went very badly for a receiver group,
	/// or an operator raise that did not hold: the group's cap went back.
	pub fn warmup_backoff(&self) {
		self.warmup_backoff.fetch_add(1, Ordering::Relaxed);
	}

	/// Count an inbound report that was too large, malformed, or whose
	/// encoding we did not support.
	pub fn reports_dropped(&self) {
		self.reports_dropped.fetch_add(1, Ordering::Relaxed);
	}

	/// Count a public MTA-STS HTTPS connection dropped before the TLS
	/// handshake because the listener's concurrency cap was already full.
	pub fn mta_sts_connections_dropped(&self) {
		self.mta_sts_connections_dropped
			.fetch_add(1, Ordering::Relaxed);
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

	/// Count an unauthenticated message accepted because its subject carried
	/// a valid SubjectPass token for the (sender, recipient, day) triple.
	pub fn subjectpass_passed(&self) {
		self.subjectpass_passed.fetch_add(1, Ordering::Relaxed);
	}

	/// Count an unauthenticated message in the uncertain band that was
	/// refused with a SubjectPass challenge (no token in the subject,
	/// and either no LLM hook or the LLM hook call failed).
	pub fn subjectpass_challenged(&self) {
		self.subjectpass_challenged.fetch_add(1, Ordering::Relaxed);
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
			RejectReason::HeaderFields => &self.rejected_header_fields,
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
			"rejected_header_fields" => &self.rejected_header_fields,
			"abuse_dropped" => &self.abuse_dropped,
			"sieve_rejected" => &self.sieve_rejected,
			"sieve_inspection_truncated" => &self.sieve_inspection_truncated,
			"vacation_sent" => &self.vacation_sent,
			"forwarded" => &self.forwarded,
			"relayed" => &self.relayed,
			"deferred" => &self.deferred,
			"bounced" => &self.bounced,
			"outbound_policy_rejected" => &self.outbound_policy_rejected,
			"webhook_sent" => &self.webhook_sent,
			"webhook_failed" => &self.webhook_failed,
			"scanner_clamd_failed" => &self.scanner_clamd_failed,
			"scanner_clamd_skipped" => &self.scanner_clamd_skipped,
			"outbound_virus" => &self.outbound_virus,
			"database_unavailable" => &self.database_unavailable,
			"clock_drift_exceeded" => &self.clock_drift_exceeded,
			"auth_login_succeeded" => &self.auth_login_succeeded,
			"auth_login_failed" => &self.auth_login_failed,
			"send_limited_new_recipients" => &self.send_limited_new_recipients,
			"bayes_training_dropped" => &self.bayes_training_dropped,
			"subjectpass_passed" => &self.subjectpass_passed,
			"subjectpass_challenged" => &self.subjectpass_challenged,
			"dmarc_reports_ingested" => &self.dmarc_reports_ingested,
			"dmarc_report_rows_failing" => &self.dmarc_report_rows_failing,
			"tlsrpt_reports_ingested" => &self.tlsrpt_reports_ingested,
			"tlsrpt_failed_sessions" => &self.tlsrpt_failed_sessions,
			"reports_dropped" => &self.reports_dropped,
			"mta_sts_connections_dropped" => &self.mta_sts_connections_dropped,
			"accept_failed" => &ACCEPT_FAILED,
			"warmup_held" => &self.warmup_held,
			"warmup_backoff" => &self.warmup_backoff,
			other => unreachable!("unknown counter field {other}"),
		}
	}
}

mod render;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
