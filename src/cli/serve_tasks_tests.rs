//! Tests for `spawn_dkim_rotation` and the pure `decide_dkim_rotation`
//! policy it consumes.
//!
//! In a sibling file (not inline) because `serve_tasks.rs` is already at
//! the per-file line ceiling for the production code it carries.

use tracing::Level;

use super::super::tracing_capture::run_with_capture;
use super::{DkimRotationPlan, connect_database, decide_dkim_rotation};
use crate::config::Config;

/// Minimal valid base config — `hostname` + `data_dir` are the only
/// unconditionally-required keys. The other sections are added per test.
const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#;

fn parse(toml: &str) -> Config {
	toml::from_str(toml).expect("parse config")
}

#[test]
fn rotation_runs_when_dns_is_present_without_rotate_days() {
	// [dkim] + [dns], no rotate_days: rotation runs with the constant
	// interval/overlap and no deprecation flag. The expected values are
	// spelled out in days and converted here so a constant change shows
	// up as a failing test.
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert_eq!(
		decide_dkim_rotation(&config),
		DkimRotationPlan::Run {
			interval: 90 * 86_400,
			overlap: 14 * 86_400,
			deprecated_fields_present: false,
		}
	);
}

#[test]
fn rotation_runs_with_constants_when_legacy_fields_are_set() {
	// The legacy `rotate_days` / `rotate_overlap_days` values are captured
	// for backward compatibility but ignored: the effective timing comes
	// from the constants (not from the file), and the deprecation flag is
	// set. The file deliberately carries different values so a test that
	// leaked the file's values would fail loudly.
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rotate_days = 7
rotate_overlap_days = 3

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert_eq!(
		decide_dkim_rotation(&config),
		DkimRotationPlan::Run {
			interval: 90 * 86_400,
			overlap: 14 * 86_400,
			deprecated_fields_present: true,
		}
	);
}

#[test]
fn rotation_is_off_without_dns_and_logs_inactive_notice() {
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
"
	));
	assert_eq!(decide_dkim_rotation(&config), DkimRotationPlan::Off);

	// The caller (`spawn_dkim_rotation`) must leave a record at startup.
	// We exercise it directly so the log emission is captured.
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None);
	});
	let notice = events
		.iter()
		.find(|e| e.level == Level::INFO)
		.expect("expected an inactivity notice when [dkim] is set but [dns] is not");
	let msg = notice
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("rotation is inactive"),
		"inactive notice must explain why: {msg}"
	);
	assert!(
		msg.contains("[dns]"),
		"inactive notice must point at the missing [dns] section: {msg}"
	);
}

#[test]
fn spawn_dkim_rotation_warns_when_legacy_rotation_fields_are_set() {
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rotate_days = 30

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert!(config.dns.is_some(), "test fixture must include [dns]");

	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None);
	});
	let warning = events
		.iter()
		.find(|e| e.level == Level::WARN)
		.expect("expected a deprecation warning for rotate_days");
	let msg = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("deprecated"),
		"warning must say the field is deprecated: {msg}"
	);
	// The effective values are spelled out so operators can confirm what
	// actually happens without reading the source.
	assert!(
		msg.contains(&format!("every {} days", crate::dkim::ROTATE_INTERVAL_DAYS)),
		"warning must state the effective interval: {msg}"
	);
	assert!(
		msg.contains(&format!("{} day overlap", crate::dkim::ROTATE_OVERLAP_DAYS)),
		"warning must state the effective overlap: {msg}"
	);
	// Structured fields are present too: useful for log search.
	assert_eq!(
		warning.fields.get("interval_days").map(String::as_str),
		Some("90")
	);
	assert_eq!(
		warning.fields.get("overlap_days").map(String::as_str),
		Some("14")
	);
}

#[test]
fn spawn_dkim_rotation_silent_when_legacy_fields_absent_and_dns_present() {
	// No legacy fields, [dns] is present: nothing deprecation-related is
	// logged (the rotation itself does spawn, but its first tick is on the
	// next hour and we don't wait for it here).
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None);
	});
	assert!(
		!events.iter().any(|e| e.level == Level::WARN),
		"clean config must not log a deprecation warning: {events:?}"
	);
	assert!(
		!events.iter().any(|e| e.level == Level::INFO),
		"clean config must not log the inactive notice: {events:?}"
	);
}

#[test]
fn rotation_is_off_when_dkim_section_is_absent() {
	// No [dkim]: there is nothing to rotate. This is intentionally silent
	// — the absence of [dkim] is visible from the surrounding config.
	let config = parse(BASE);
	assert_eq!(decide_dkim_rotation(&config), DkimRotationPlan::Off);

	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None);
	});
	assert!(
		events.is_empty(),
		"absent [dkim] must not log anything (the operator chose it): {events:?}"
	);
}

// --- database startup -----------------------------------------------------

/// A minimal config with a `[database]` section pointing at a host that cannot
/// resolve, so `connect_database` always takes a failure branch.
fn config_with_unreachable_database(directory: bool) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp\"\n\n\
		 [database]\nurl = \"postgres://mail@db.invalid/mail\"\ndirectory = {directory}\n"
	);
	toml::from_str(&toml).expect("config")
}

#[tokio::test]
async fn no_database_section_yields_no_pool() {
	let config: Config =
		toml::from_str("hostname = \"mail.example.org\"\ndata_dir = \"/tmp\"\n").expect("config");
	let metrics = crate::metrics::Metrics::new();
	let pool = connect_database(&config, &metrics)
		.await
		.expect("no database is not an error");
	assert!(pool.is_none());
	assert_eq!(metrics.snapshot().get("database_unavailable"), Some(&0));
}

#[tokio::test]
async fn unreachable_database_without_directory_starts_and_counts() {
	let config = config_with_unreachable_database(false);
	let metrics = crate::metrics::Metrics::new();
	let pool = connect_database(&config, &metrics)
		.await
		.expect("an antispam-only database must not stop the start");
	// Degraded: no pool, so every consumer sees the same shape as no database.
	assert!(pool.is_none());
	// The warning alone is not an alert; the counter is what the alert engine reads.
	assert_eq!(metrics.snapshot().get("database_unavailable"), Some(&1));
	assert!(
		metrics
			.render()
			.contains("mail_database_unavailable_total 1\n"),
		"{}",
		metrics.render()
	);
}

#[tokio::test]
async fn unreachable_database_with_directory_is_fatal_and_says_why() {
	let config = config_with_unreachable_database(true);
	let metrics = crate::metrics::Metrics::new();
	let error = connect_database(&config, &metrics)
		.await
		.expect_err("the SQL directory cannot degrade");
	let message = error.to_string();
	// The operator has to be able to tell this fatal case from the degraded one.
	assert!(message.contains("directory = true"), "{message}");
	assert!(
		message.contains("accounts are resolved from it"),
		"{message}"
	);
	assert!(message.contains("fatal for that reason only"), "{message}");
	// A fatal start is not a degradation, so it must not fire the advisory counter.
	assert_eq!(metrics.snapshot().get("database_unavailable"), Some(&0));
}
