//! The Prometheus text rendering of [`Metrics`], kept apart from the
//! counters themselves so the list of what is counted stays readable.

use std::sync::atomic::Ordering;

use super::{ACCEPT_FAILED, Metrics, REASONS};

impl Metrics {
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
				"mail_outbound_policy_rejected_total",
				"Outbound recipients refused on policy grounds (5.7.x): check the sending reputation.",
				&self.outbound_policy_rejected,
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
				"mail_scanner_clamd_failed_total",
				"Clamd scan failures that accepted the message.",
				&self.scanner_clamd_failed,
			),
			(
				"mail_scanner_clamd_skipped_total",
				"Messages skipped because they exceeded the clamd byte limit.",
				&self.scanner_clamd_skipped,
			),
			(
				"mail_outbound_virus_total",
				"Submissions by local accounts that the antivirus refused.",
				&self.outbound_virus,
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
				"mail_dmarc_reports_ingested_total",
				"DMARC aggregate reports successfully ingested from a receiver.",
				&self.dmarc_reports_ingested,
			),
			(
				"mail_dmarc_report_rows_failing_total",
				"DMARC report rows whose disposition was quarantine/reject or whose SPF and DKIM both failed.",
				&self.dmarc_report_rows_failing,
			),
			(
				"mail_tlsrpt_reports_ingested_total",
				"TLS-RPT reports successfully ingested from a receiver.",
				&self.tlsrpt_reports_ingested,
			),
			(
				"mail_tlsrpt_failed_sessions_total",
				"Outbound TLS sessions the receivers reported as failed across ingested TLS-RPT reports.",
				&self.tlsrpt_failed_sessions,
			),
			(
				"mail_reports_dropped_total",
				"Inbound DMARC or TLS-RPT reports dropped for being too large, malformed, or using an unsupported encoding.",
				&self.reports_dropped,
			),
			(
				"mail_mta_sts_connections_dropped_total",
				"Public MTA-STS HTTPS connections dropped before the TLS handshake because the listener's concurrency cap was full.",
				&self.mta_sts_connections_dropped,
			),
			(
				"mail_warmup_held_total",
				"IP warm-up days that went badly for a receiver group; its cap held.",
				&self.warmup_held,
			),
			(
				"mail_warmup_backoff_total",
				"IP warm-up days that went very badly for a receiver group, or raises that did not hold; its cap went back.",
				&self.warmup_backoff,
			),
			(
				"mail_accept_failed_total",
				"Failed accepts on any listener (out of descriptors, aborted connections); the listener keeps running.",
				&ACCEPT_FAILED,
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
			(
				"mail_send_limited_new_recipients_total",
				"Submissions refused because the account would exceed the daily cap on first-time recipients.",
				&self.send_limited_new_recipients,
			),
			(
				"mail_bayes_training_dropped_total",
				"Bayesian training jobs dropped: a bounded hand-off queue was full, or the source had used its share of the shared corpus.",
				&self.bayes_training_dropped,
			),
			(
				"mail_subjectpass_passed_total",
				"Unauthenticated messages accepted by a valid SubjectPass token in the subject.",
				&self.subjectpass_passed,
			),
			(
				"mail_subjectpass_challenged_total",
				"Unauthenticated messages refused with a SubjectPass challenge.",
				&self.subjectpass_challenged,
			),
		] {
			out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
			out.push_str(&format!("{name} {}\n", counter.load(Ordering::Relaxed)));
		}
		out
	}
}
