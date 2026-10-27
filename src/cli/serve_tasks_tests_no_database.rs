//! Tests for `connect_database`'s startup warning when no `[database]`
//! is configured. Sibling (`serve_tasks_tests.rs`) is at the per-file
//! line cap for the dkim + connect_database cases; the no-database
//! warning tests live here so neither file crosses 500.

use std::sync::Arc;

use super::super::trace::capture::run_with_capture;
use super::connect_database;
use crate::config::Config;

/// A config with no `[database]` triggers a startup warning that names
/// every antispam feature that requires one. Operators see it in the
/// same startup window every other warning lands in, so a
/// misconfigured install surfaces without log scraping.
const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#;

fn parse(toml: &str) -> Config {
	toml::from_str(toml).expect("parse config")
}

#[tokio::test(flavor = "multi_thread")]
async fn no_database_logs_one_warning_listing_every_off_feature() {
	let config = parse(BASE);
	assert!(
		config.database.is_none(),
		"the fixture must omit [database]"
	);
	// Greylist as a feature needs the warning: pick a delay that
	// forces it.
	let mut config = config;
	config.greylist_delay_secs = 60;
	// `block_in_place` lets the test drive a sync `run_with_capture`
	// around the async `connect_database` call: the subscriber
	// captures the warnings emitted inside the awaited future.
	let events = tokio::task::block_in_place(|| {
		run_with_capture(|| {
			let runtime = tokio::runtime::Handle::current();
			runtime.block_on(async {
				let metrics = Arc::new(crate::metrics::Metrics::new());
				let pool = connect_database(&config, &metrics)
					.await
					.expect("no [database] is not an error");
				assert!(pool.is_none(), "no [database] yields no pool");
			})
		})
	});
	let warning = events
		.iter()
		.find(|event| event.level == tracing::Level::WARN)
		.expect("expected a startup warning for the missing [database]");
	let message = warning
		.fields
		.get("message")
		.expect("warning carries a message field")
		.as_str();
	assert!(
		message.contains("[database]"),
		"warning must point at the missing section: {message}"
	);
	for feature in ["Bayes", "reputation", "greylist", "ban"] {
		assert!(
			message.contains(feature),
			"warning must name the `{feature}` feature: {message}"
		);
	}
}

/// The warning is suppressed when the install is clearly minimal:
/// greylist disabled and SubjectPass off. The warning's purpose is to
/// flag surprises, and these two being off together means the
/// operator chose a no-antispam profile.
#[tokio::test(flavor = "multi_thread")]
async fn no_database_warning_stays_silent_for_minimal_installs() {
	let config = parse(BASE);
	assert!(config.database.is_none(), "fixture must omit [database]");
	assert!(
		config.greylist_delay_secs == 0,
		"no greylist on a minimal install"
	);
	assert!(
		!config.subjectpass.enabled,
		"no subjectpass on a minimal install"
	);
	let events = tokio::task::block_in_place(|| {
		run_with_capture(|| {
			let runtime = tokio::runtime::Handle::current();
			runtime.block_on(async {
				let metrics = Arc::new(crate::metrics::Metrics::new());
				let _ = connect_database(&config, &metrics)
					.await
					.expect("no [database] is not an error");
			})
		})
	});
	assert!(
		!events
			.iter()
			.any(|event| event.level == tracing::Level::WARN),
		"a minimal install must not produce the warning: {events:?}"
	);
}

/// Greylisting enabled makes the warning fire even when nothing else
/// is configured, because the operator opted into a feature that does
/// need a database for its persistent state.
#[tokio::test(flavor = "multi_thread")]
async fn no_database_warning_fires_when_greylist_is_on() {
	let config = parse(&format!("{BASE}\ngreylist_delay_secs = 60\n"));
	assert!(config.database.is_none());
	assert!(config.greylist_delay_secs > 0);
	let events = tokio::task::block_in_place(|| {
		run_with_capture(|| {
			let runtime = tokio::runtime::Handle::current();
			runtime.block_on(async {
				let metrics = Arc::new(crate::metrics::Metrics::new());
				let _ = connect_database(&config, &metrics)
					.await
					.expect("no [database] is not an error");
			})
		})
	});
	let warning = events
		.iter()
		.find(|event| event.level == tracing::Level::WARN)
		.expect("greylist on its own must trigger the warning");
	let message = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		message.contains("greylist"),
		"warning must mention the greylist feature the operator enabled: {message}"
	);
}
