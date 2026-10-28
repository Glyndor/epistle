use super::*;

#[test]
fn tlsrpt_reports_default_on_and_can_be_turned_off() {
	assert!(Queue::default().tlsrpt_reports);
	let parsed: Queue = toml::from_str("outbound_tls = \"strict\"").expect("parse");
	assert!(parsed.tlsrpt_reports);
	let off: Queue = toml::from_str("tlsrpt_reports = false").expect("parse");
	assert!(!off.tlsrpt_reports);
}

fn with_queue(section: &str) -> crate::config::Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[queue]\n{section}"
	))
	.expect("parse")
}

#[test]
fn concurrency_out_of_range_is_refused() {
	for (section, message) in [
		(
			"concurrency = 0",
			"[queue] concurrency must be between 1 and 1024 (got 0)",
		),
		(
			"concurrency = 1025",
			"[queue] concurrency must be between 1 and 1024 (got 1025)",
		),
		(
			"per_domain_concurrency = 0",
			"[queue] per_domain_concurrency must be between 1 and concurrency (8) (got 0)",
		),
		(
			"concurrency = 4\nper_domain_concurrency = 5",
			"[queue] per_domain_concurrency must be between 1 and concurrency (4) (got 5)",
		),
	] {
		let error = with_queue(section)
			.validate_queue_limits()
			.expect_err(section);
		assert_eq!(
			error.to_string(),
			format!("invalid configuration: {message}")
		);
	}
	assert!(
		with_queue("concurrency = 16\nper_domain_concurrency = 16")
			.validate_queue_limits()
			.is_ok()
	);
}

#[test]
fn backoff_steps_default_parse_and_are_bounded() {
	assert_eq!(Queue::default().backoff_steps, [60, 300, 900, 3600]);
	let parsed = with_queue("backoff_steps = [30, 120]");
	assert_eq!(parsed.queue.backoff_steps, [30, 120]);
	assert!(parsed.validate_queue_limits().is_ok());
	for (section, message) in [
		(
			"backoff_steps = []",
			"[queue] backoff_steps must have between 1 and 16 steps (got 0)",
		),
		(
			"backoff_steps = [60, 0]",
			"[queue] backoff_steps must be between 1 and 86400 seconds each (got 0)",
		),
		(
			"backoff_steps = [86401]",
			"[queue] backoff_steps must be between 1 and 86400 seconds each (got 86401)",
		),
	] {
		let error = with_queue(section)
			.validate_queue_limits()
			.expect_err(section);
		assert_eq!(
			error.to_string(),
			format!("invalid configuration: {message}")
		);
	}
}

#[test]
fn concurrency_defaults_and_parses() {
	let defaults = Queue::default();
	assert_eq!(
		(defaults.concurrency, defaults.per_domain_concurrency),
		(8, 2)
	);
	let parsed: Queue =
		toml::from_str("concurrency = 20\nper_domain_concurrency = 4").expect("parse");
	assert_eq!((parsed.concurrency, parsed.per_domain_concurrency), (20, 4));
}
