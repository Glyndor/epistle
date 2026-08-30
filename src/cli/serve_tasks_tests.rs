//! Tests for `spawn_dkim_rotation` and the pure `decide_dkim_rotation`
//! policy it consumes.
//!
//! In a sibling file (not inline) because `serve_tasks.rs` is already at
//! the per-file line ceiling for the production code it carries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::Level;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;

/// Minimal valid base config — `hostname` + `data_dir` are the only
/// unconditionally-required keys. The other sections are added per test.
const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#;

#[derive(Clone, Debug)]
struct CapturedEvent {
	level: Level,
	fields: HashMap<String, String>,
}

#[derive(Default)]
struct Capture {
	events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
		let mut fields = HashMap::new();
		event.record(&mut FieldVisitor {
			fields: &mut fields,
		});
		self.events.lock().unwrap().push(CapturedEvent {
			level: *event.metadata().level(),
			fields,
		});
	}
}

struct FieldVisitor<'a> {
	fields: &'a mut HashMap<String, String>,
}

impl Visit for FieldVisitor<'_> {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.fields
			.insert(field.name().to_string(), format!("{value:?}"));
	}
	fn record_str(&mut self, field: &Field, value: &str) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
	fn record_i64(&mut self, field: &Field, value: i64) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
	fn record_u64(&mut self, field: &Field, value: u64) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
	fn record_bool(&mut self, field: &Field, value: bool) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
}

/// Run `f` with a thread-local subscriber that captures every emitted
/// tracing event, then return the captured set.
fn run_with_capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
	let cap = Capture::default();
	let events = cap.events.clone();
	let subscriber = Registry::default().with(cap);
	tracing::subscriber::with_default(subscriber, f);
	Arc::try_unwrap(events)
		.map(|m| m.into_inner().unwrap())
		.unwrap_or_default()
}

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
