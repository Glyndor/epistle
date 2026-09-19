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
	m.report_ingested(crate::reports::Kind::Dmarc);
	m.report_ingested(crate::reports::Kind::TlsRpt);
	m.report_rows_failing(crate::reports::Kind::Dmarc, 7);
	m.report_rows_failing(crate::reports::Kind::TlsRpt, 4);
	m.reports_dropped();
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
	assert!(r.contains("mail_dmarc_reports_ingested_total 1\n"), "{r}");
	assert!(r.contains("mail_tlsrpt_reports_ingested_total 1\n"), "{r}");
	assert!(
		r.contains("mail_dmarc_report_rows_failing_total 7\n"),
		"{r}"
	);
	assert!(r.contains("mail_tlsrpt_failed_sessions_total 4\n"), "{r}");
	assert!(r.contains("mail_reports_dropped_total 1\n"), "{r}");
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
		"scanner_clamd_failed",
		"scanner_clamd_skipped",
		"database_unavailable",
		"clock_drift_exceeded",
		"auth_login_succeeded",
		"auth_login_failed",
		"send_limited_new_recipients",
		"bayes_training_dropped",
		"subjectpass_passed",
		"subjectpass_challenged",
		"dmarc_reports_ingested",
		"dmarc_report_rows_failing",
		"tlsrpt_reports_ingested",
		"tlsrpt_failed_sessions",
		"reports_dropped",
	] {
		assert!(snap.contains_key(name), "missing {name}");
	}
}

#[test]
fn clamd_counters_render_and_snapshot_independently() {
	let metrics = Metrics::new();
	metrics.scanner_clamd_failed();
	metrics.scanner_clamd_skipped();
	metrics.scanner_clamd_skipped();
	let snapshot = metrics.snapshot();
	assert_eq!(snapshot.get("scanner_clamd_failed"), Some(&1));
	assert_eq!(snapshot.get("scanner_clamd_skipped"), Some(&2));
	let rendered = metrics.render();
	for (name, count) in [("scanner_clamd_failed", 1), ("scanner_clamd_skipped", 2)] {
		assert!(metric_names().contains(&name));
		assert!(rendered.contains(&format!("# TYPE mail_{name}_total counter\n")));
		assert!(rendered.contains(&format!("# HELP mail_{name}_total ")));
		assert!(rendered.contains(&format!("mail_{name}_total {count}\n")));
	}
}
