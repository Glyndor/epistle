//! Tests for the password-based authentication audit channel.
//!
//! Every call to [`super::Directory::authenticate_with_ip`] must emit one
//! structured tracing event on the `epistle::auth` target (success or
//! failure), and must bump the right counter when a metrics handle is
//! attached. The plaintext password and the TOTP code are never written
//! to the log: that is the property these tests guard.
//!
//! The capture layer is the same pattern as
//! `crate::config::validate_tests_b`: a `tracing_subscriber::Layer` installed
//! with `tracing::subscriber::with_default`, so the subscriber guard stays
//! alive for the whole closure. The failure message of a no-leak assert
//! names the violated property and the fields involved, never the captured
//! blob — printing it is the leak (`src/config/redaction_tests.rs`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::*;

#[derive(Clone, Debug)]
struct CapturedEvent {
	target: String,
	fields: HashMap<String, String>,
	message: String,
}

#[derive(Default)]
struct Capture {
	events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
		let mut fields = HashMap::new();
		let mut message = String::new();
		event.record(&mut FieldVisitor {
			fields: &mut fields,
			message: &mut message,
		});
		self.events.lock().unwrap().push(CapturedEvent {
			target: event.metadata().target().to_string(),
			fields,
			message,
		});
	}
}

struct FieldVisitor<'a> {
	fields: &'a mut HashMap<String, String>,
	message: &'a mut String,
}

impl Visit for FieldVisitor<'_> {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		if field.name() == "message" {
			*self.message = format!("{value:?}");
		} else {
			self.fields
				.insert(field.name().to_string(), format!("{value:?}"));
		}
	}
	fn record_str(&mut self, field: &Field, value: &str) {
		if field.name() == "message" {
			*self.message = value.to_string();
		} else {
			self.fields
				.insert(field.name().to_string(), value.to_string());
		}
	}
}

/// Drive `f` with a thread-local subscriber that captures every emitted
/// tracing event, then return the captured set.
fn run_with_capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
	let cap = Capture::default();
	let events = cap.events.clone();
	let subscriber = Registry::default().with(LevelFilter::INFO).with(cap);
	tracing::subscriber::with_default(subscriber, f);
	Arc::try_unwrap(events)
		.map(|m| m.into_inner().unwrap())
		.unwrap_or_default()
}

fn auth_events(events: &[CapturedEvent]) -> Vec<&CapturedEvent> {
	events
		.iter()
		.filter(|event| event.target == "epistle::auth")
		.collect()
}

fn auth_blob(events: &[CapturedEvent]) -> String {
	let mut blob = String::new();
	for event in events {
		for value in event.fields.values() {
			blob.push_str(value);
			blob.push('\n');
		}
		blob.push_str(&event.message);
		blob.push('\n');
	}
	blob
}

fn directory_with_alice(secret: &str) -> Directory {
	Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([("alice".to_string(), crate::smtp::auth::tests::hash(secret))])
}

/// A successful password authentication must emit exactly one
/// `auth.login_succeeded` event carrying the resolved account, the login
/// the client presented, and the peer IP — and nothing else. The counter
/// `auth_login_succeeded` must move by exactly one.
#[test]
fn success_emits_login_succeeded_event_and_bumps_counter() {
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let directory = directory_with_alice("hunter2").with_metrics(metrics.clone());

	let peer: std::net::IpAddr = "203.0.113.7".parse().expect("peer");
	let events = run_with_capture(|| {
		assert_eq!(
			directory
				.authenticate_with_ip("alice", "hunter2", Some(peer), crate::config::Protocol::Api)
				.as_deref(),
			Some("alice"),
		);
	});

	let auth = auth_events(&events);
	assert_eq!(
		auth.len(),
		1,
		"exactly one auth event expected on the epistle::auth target"
	);
	assert_eq!(
		auth[0].fields.get("event").map(String::as_str),
		Some("auth.login_succeeded"),
	);
	assert_eq!(
		auth[0].fields.get("login").map(String::as_str),
		Some("alice"),
	);
	assert_eq!(
		auth[0].fields.get("account").map(String::as_str),
		Some("alice"),
	);
	assert_eq!(
		auth[0].fields.get("client_ip").map(String::as_str),
		Some("203.0.113.7"),
	);

	assert_eq!(
		metrics.snapshot().get("auth_login_succeeded").copied(),
		Some(1),
	);
	assert_eq!(
		metrics.snapshot().get("auth_login_failed").copied(),
		Some(0),
	);
}

/// A wrong password must emit `auth.login_failed` and bump the failure
/// counter. The account field is rendered as `unknown` regardless of
/// whether the login resolved, mirroring the wire-level no-oracle
/// contract: a wrong password and an unknown login produce the same
/// `Some/None` outcome, and the audit log carries that same anonymity
/// across the threshold.
#[test]
fn wrong_password_emits_login_failed_event_and_bumps_counter() {
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let directory = directory_with_alice("hunter2").with_metrics(metrics.clone());

	let events = run_with_capture(|| {
		assert!(
			directory
				.authenticate_with_ip("alice", "not-it", None, crate::config::Protocol::Api)
				.is_none(),
		);
	});

	let auth = auth_events(&events);
	assert_eq!(auth.len(), 1, "exactly one auth event expected");
	assert_eq!(
		auth[0].fields.get("event").map(String::as_str),
		Some("auth.login_failed"),
	);
	assert_eq!(
		auth[0].fields.get("login").map(String::as_str),
		Some("alice"),
	);
	assert_eq!(
		auth[0].fields.get("account").map(String::as_str),
		Some("unknown"),
		"a failed attempt must not leak whether the account exists",
	);
	assert_eq!(
		auth[0].fields.get("client_ip").map(String::as_str),
		Some("unknown"),
	);

	assert_eq!(
		metrics.snapshot().get("auth_login_failed").copied(),
		Some(1),
	);
	assert_eq!(
		metrics.snapshot().get("auth_login_succeeded").copied(),
		Some(0),
	);
}

/// An unknown login must emit `auth.login_failed` with `account =
/// "unknown"` (we never reveal whether the account exists in the audit
/// log either, since operators correlate by `login`+`client_ip` and the
/// wire response is `None` for both an unknown account and a wrong
/// password). The counter still moves.
#[test]
fn unknown_login_emits_login_failed_event() {
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let directory = directory_with_alice("hunter2").with_metrics(metrics.clone());

	let events = run_with_capture(|| {
		assert!(
			directory
				.authenticate_with_ip("mallory", "anything", None, crate::config::Protocol::Api)
				.is_none()
		);
	});

	let auth = auth_events(&events);
	assert_eq!(auth.len(), 1);
	assert_eq!(
		auth[0].fields.get("event").map(String::as_str),
		Some("auth.login_failed"),
	);
	assert_eq!(
		auth[0].fields.get("login").map(String::as_str),
		Some("mallory"),
	);
	assert_eq!(
		auth[0].fields.get("account").map(String::as_str),
		Some("unknown"),
		"unknown login must not leak its account-existed-ness into the log",
	);

	assert_eq!(
		metrics.snapshot().get("auth_login_failed").copied(),
		Some(1),
	);
}

/// The audit channel must never carry the plaintext password nor the TOTP
/// code. The lesson from `src/config/redaction_tests.rs` applies: a test
/// that printed the captured blob on failure would leak on the very run
/// the assertion was meant to guard, so the failure message names the
/// property and the input fields but never the blob.
///
/// We exercise both a TOTP-equipped success and a wrong-password failure
/// (the two code paths that touch the secret material directly), require
/// the events to actually have been emitted — without this precondition
/// the no-leak check is vacuously true and would not catch a regression
/// that simply stopped emitting the channel — and only then assert the
/// secret is absent from the captured fields.
#[test]
fn captured_log_never_carries_password_or_totp_code() {
	let secret = b"do-not-leak-secret-bytes!";
	let totp_b32 = crate::totp::encode_base32(secret);
	let directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([(
		"alice".to_string(),
		crate::smtp::auth::tests::hash("a-very-secret-password"),
	)])
	.with_totp([("alice".to_string(), totp_b32.clone())]);

	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let code = crate::totp::totp(secret, now);

	let events = run_with_capture(|| {
		// Two attempts: one success that exercised TOTP, one failure with
		// a wrong password. Both must land on the audit channel without
		// carrying the secret in any field.
		let combined = format!("a-very-secret-password{code:06}");
		assert_eq!(
			directory
				.authenticate_with_ip("alice", &combined, None, crate::config::Protocol::Api)
				.as_deref(),
			Some("alice"),
		);
		assert!(
			directory
				.authenticate_with_ip(
					"alice",
					"a-very-secret-password",
					None,
					crate::config::Protocol::Api
				)
				.is_none(),
		);
	});

	let auth = auth_events(&events);
	assert_eq!(
		auth.len(),
		2,
		"expected one success and one failure event — the no-leak check \
		 below is only meaningful if the channel actually fires",
	);

	let blob = auth_blob(&events);
	assert!(
		!blob.contains("a-very-secret-password"),
		"audit channel leaked the plaintext password in some field",
	);
	assert!(
		!blob.contains(&format!("{code:06}")),
		"audit channel leaked the TOTP code in some field",
	);
	// Belt-and-braces: the unwrapped base32 secret must not be there
	// either, even though the directory never sees it in plaintext at the
	// `authenticate` boundary. (This is the regression test that would
	// catch a future change that started serialising the configured TOTP
	// entry into the audit event.)
	assert!(
		!blob.contains(&totp_b32),
		"audit channel leaked the TOTP secret in some field",
	);
}
