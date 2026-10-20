//! SHOULD warnings: `queue_give_up_secs` below the RFC-recommended 4
//! days and `queue_retry_base_secs` below 30 minutes are accepted
//! with a warning, never refused. The warning is emitted by both
//! `epistle limits set` and `serve` start-up, sourced from the same
//! `Config::retry_schedule_warnings` helper.

use std::process::ExitCode;

use super::tests_session_limits::limits;

#[test]
fn queue_give_up_below_four_days_warns_and_is_saved() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "queue-give-up", "86400"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	assert!(
		printed.contains("warning: queue-give-up is below the 4 days RFC 5321 §4.5.4.1 recommends"),
		"the saved value must carry the SHOULD warning: {printed}"
	);
}

#[test]
fn queue_give_up_above_four_days_is_saved_without_warning() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "queue-give-up", "345600"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	assert!(
		!printed.contains("warning"),
		"the saved value at the recommended floor must not warn: {printed}"
	);
}

#[test]
fn queue_retry_base_below_thirty_minutes_warns_and_is_saved() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "queue-retry-base", "120"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	assert!(
		printed.contains("warning: queue-retry-base is below the 30 minutes the RFC recommends"),
		"the saved value must carry the SHOULD warning: {printed}"
	);
}

#[test]
fn queue_retry_base_at_thirty_minutes_is_saved_without_warning() {
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "queue-retry-base", "1800"]);
	assert_eq!(code, ExitCode::SUCCESS, "{printed}");
	assert!(
		!printed.contains("warning"),
		"the saved value at the recommended floor must not warn: {printed}"
	);
}

#[test]
fn a_setting_that_breaks_the_hard_floor_is_still_refused() {
	// The hard floor (`queue_retry_base_secs >= 60`) from
	// `validate_retry_schedule` stays in force: the SHOULD warning is a
	// separate, advisory rule. Below 60 the `set` still fails.
	let (_dir, file) = super::tests_config::config_file();
	let (code, printed) = limits(file.path(), &["set", "queue-retry-base", "30"]);
	assert_eq!(code, ExitCode::FAILURE, "{printed}");
	assert!(
		printed.contains("queue_retry_base_secs must be at least"),
		"the historical hard floor stays: {printed}"
	);
}

#[test]
fn the_retry_schedule_warnings_match_the_runtime_text() {
	use crate::config::Config;
	let parsed = |section: &str| -> Config {
		let raw =
			format!("hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{section}");
		toml::from_str(&raw).expect("parse")
	};
	// A one-day give-up with a 30-minute first retry: exactly one
	// warning (the give-up one).
	let warnings = parsed("queue_give_up_secs = 86400\nqueue_retry_base_secs = 1800")
		.retry_schedule_warnings();
	assert_eq!(
		warnings.len(),
		1,
		"a give-up of one day (with a 30-minute retry base) yields exactly the SHOULD warning: {warnings:?}"
	);
	assert!(
		warnings[0].contains("RFC 5321 §4.5.4.1"),
		"the runtime warning text agrees with `limits set`"
	);
	assert!(
		parsed("queue_give_up_secs = 345600\nqueue_retry_base_secs = 1800")
			.retry_schedule_warnings()
			.is_empty(),
		"a four-day give-up yields no SHOULD warning"
	);
	// A one-minute first retry with a five-day give-up: exactly one
	// warning (the retry-base one).
	let warnings =
		parsed("queue_retry_base_secs = 60\nqueue_give_up_secs = 432000").retry_schedule_warnings();
	assert_eq!(
		warnings.len(),
		1,
		"a one-minute first retry yields the retry-base SHOULD warning: {warnings:?}"
	);
	assert!(
		parsed("queue_retry_base_secs = 1800\nqueue_give_up_secs = 432000")
			.retry_schedule_warnings()
			.is_empty()
	);
}
