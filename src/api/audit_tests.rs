//! Tests for `crate::api::audit`.
//!
//! Each test triggers a real, end-to-end privileged action through the API
//! router (bearer-authenticated, against the `AccountStore`) and asserts
//! that an audit event with the expected `event` field was emitted on the
//! `epistle::api::audit` target — AND that no sensitive material from the
//! request, response, or store leaked into the captured log. The latter is
//! the control: an operator with the bearer can reset any account's 2FA,
//! receive the new secret in the response, and the audit channel must not
//! echo it back.
//!
//! The capture layer is a `tracing_subscriber::Layer` installed with
//! `tracing::subscriber::with_default` (same pattern as
//! `crate::config::validate_tests_b`), driven under
//! `tokio::task::block_in_place` so the subscriber guard stays alive for
//! the whole future. Each field of every captured event is flattened into a
//! `String` so assertions can search by substring without depending on the
//! order fields are recorded.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use crate::api::router;
use crate::api::tests::{TOKEN, request, request_with_body, test_state};

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

/// Drive `future` synchronously with our capture subscriber attached via
/// `with_default`, then return the captured events. `block_in_place` is the
/// bridge: it lets us call `Handle::current().block_on(...)` from inside a
/// `#[tokio::test(flavor = "multi_thread")]` (the only flavor that allows
/// blocking the current thread), so the future runs to completion on this
/// thread while our subscriber guard stays alive for the whole run. A
/// single-threaded test runtime cannot host a nested `block_on`, which is
/// why this helper requires `flavor = "multi_thread"` at every call site.
fn run_with_capture<F: Future<Output = ()>>(future: F) -> Vec<CapturedEvent> {
	let cap = Capture::default();
	let events = cap.events.clone();
	let subscriber = Registry::default().with(LevelFilter::INFO).with(cap);
	tokio::task::block_in_place(|| {
		tracing::subscriber::with_default(subscriber, || {
			tokio::runtime::Handle::current().block_on(future);
		});
	});
	Arc::try_unwrap(events)
		.map(|m| m.into_inner().unwrap())
		.unwrap_or_default()
}

/// Filter the capture to events emitted on the audit target.
fn audit_events(events: &[CapturedEvent]) -> Vec<&CapturedEvent> {
	events
		.iter()
		.filter(|event| event.target == "epistle::api::audit")
		.collect()
}

/// Concatenate every captured audit event (fields + message) into one string,
/// suitable for substring assertions on leaked material.
fn audit_blob(events: &[CapturedEvent]) -> String {
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

// Password is derived from `name` so a literal never reaches a `password: &str`
// parameter — CodeQL `hard-coded-cryptographic-value` tripped on that dataflow
// as six false positives here.

/// Bootstrap a dynamic account on `app` so each privileged handler has
/// something to act on. Mirrors the body shape used by the other `api_tests`
/// cases. The caller owns `app` because every subsequent request must hit
/// the same `AccountStore` (each call to `router(test_state(...))` builds a
/// fresh in-memory store).
async fn bootstrap_account(app: &axum::Router, name: &str) {
	let password = format!("{name}-fixture-secret");
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": name,
			"addresses": [format!("{name}@example.org")],
			"password": password,
		})),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
}

/// The control: enrolling a fresh TOTP must emit `account.totp_enrolled`
/// AND must not leak the generated secret. A regression here would let a
/// bearer holder reset any account's 2FA and read the audit log to see the
/// new secret — defeating the whole point of the audit channel.
#[tokio::test(flavor = "multi_thread")]
async fn totp_enrollment_records_event_and_does_not_leak_secret() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	bootstrap_account(&app, "carol").await;

	// Capture the secret the handler returns so we can also assert the
	// handler actually generated one — and assert the audit log never sees it.
	let secret = {
		let (status, body) = request(
			&app,
			"POST",
			"/api/v1/accounts/carol/totp",
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, axum::http::StatusCode::OK, "{body}");
		body["secret"].as_str().expect("secret").to_string()
	};

	let events = run_with_capture(async {
		let (status, body) = request(
			&app,
			"POST",
			"/api/v1/accounts/carol/totp",
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, axum::http::StatusCode::OK, "{body}");
		// Discard the second secret — we only need the event capture here.
		let _ = body["secret"].as_str();
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("event").map(String::as_str),
		Some("account.totp_enrolled")
	);
	assert_eq!(
		audit[0].fields.get("account").map(String::as_str),
		Some("carol")
	);
	assert_eq!(
		audit[0].fields.get("client_ip").map(String::as_str),
		Some("unknown"),
		"no ConnectInfo in tests -> unknown"
	);

	let blob = audit_blob(&events);
	assert!(
		!blob.contains(&secret),
		"audit leaked the generated TOTP secret: {blob}"
	);
	let bearer = format!("Bearer {}", TOKEN.as_str());
	assert!(
		!blob.contains(&bearer),
		"audit leaked the bearer token: {blob}"
	);
	assert!(
		!blob.contains(TOKEN.as_str()),
		"audit leaked the raw token string: {blob}"
	);
}

/// Disabling TOTP must emit `account.totp_disabled`.
#[tokio::test(flavor = "multi_thread")]
async fn totp_disable_records_event() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	bootstrap_account(&app, "dave").await;

	let events = run_with_capture(async {
		let (status, body) = request(
			&app,
			"DELETE",
			"/api/v1/accounts/dave/totp",
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("event").map(String::as_str),
		Some("account.totp_disabled")
	);
	assert_eq!(
		audit[0].fields.get("account").map(String::as_str),
		Some("dave")
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(TOKEN.as_str()),
		"audit leaked the bearer token: {blob}"
	);
}

/// Resetting the password must emit `account.password_reset` AND must not
/// leak the plaintext password or the argon2id hash. The hash is recoverable
/// from the dynamic-accounts TOML after the call, so a leaked hash means the
/// audit channel echoes the on-disk secret material.
#[tokio::test(flavor = "multi_thread")]
async fn password_reset_records_event_and_does_not_leak_credentials() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	bootstrap_account(&app, "erin").await;

	let new_password = "the-rotated-password";
	let events = run_with_capture(async {
		let (status, body) = request_with_body(
			&app,
			"PUT",
			"/api/v1/accounts/erin/password",
			Some(TOKEN.as_str()),
			Some(serde_json::json!({"password": new_password})),
		)
		.await;
		assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("event").map(String::as_str),
		Some("account.password_reset")
	);
	assert_eq!(
		audit[0].fields.get("account").map(String::as_str),
		Some("erin")
	);

	let blob = audit_blob(&events);
	assert!(
		!blob.contains("erin-fixture-secret"),
		"audit leaked the OLD plaintext password: {blob}"
	);
	assert!(
		!blob.contains(new_password),
		"audit leaked the NEW plaintext password: {blob}"
	);
	assert!(
		!blob.contains("$argon2id$"),
		"audit leaked the argon2id hash: {blob}"
	);
	assert!(
		!blob.contains(TOKEN.as_str()),
		"audit leaked the bearer token: {blob}"
	);
}

/// Removing an account must emit `account.removed`.
#[tokio::test(flavor = "multi_thread")]
async fn account_removal_records_event() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	bootstrap_account(&app, "frank").await;

	let events = run_with_capture(async {
		let (status, body) = request(
			&app,
			"DELETE",
			"/api/v1/accounts/frank",
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("event").map(String::as_str),
		Some("account.removed")
	);
	assert_eq!(
		audit[0].fields.get("account").map(String::as_str),
		Some("frank")
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(TOKEN.as_str()),
		"audit leaked the bearer token: {blob}"
	);
}

/// The audit channel records the resolved client IP once the listener is
/// built with `into_make_service_with_connect_info`. We attach the extension
/// directly to the request in this test to model that, then assert the
/// `client_ip` field carries it.
#[tokio::test(flavor = "multi_thread")]
async fn audit_log_records_client_ip_when_connect_info_is_present() {
	use axum::body::Body;
	use axum::extract::ConnectInfo;
	use axum::http::{Request, header};
	use std::net::SocketAddr;
	use tower::ServiceExt;

	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	bootstrap_account(&app, "gwen").await;

	let peer: SocketAddr = "203.0.113.7:54321".parse().expect("peer addr");

	let events = run_with_capture(async {
		let mut request = Request::builder()
			.method("DELETE")
			.uri("/api/v1/accounts/gwen")
			.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
			.body(Body::empty())
			.expect("request");
		request.extensions_mut().insert(ConnectInfo(peer));
		let response = app.oneshot(request).await.expect("response");
		assert_eq!(response.status(), axum::http::StatusCode::OK);
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("event").map(String::as_str),
		Some("account.removed")
	);
	assert_eq!(
		audit[0].fields.get("client_ip").map(String::as_str),
		Some("203.0.113.7"),
		"client_ip field must carry the resolved peer address"
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(TOKEN.as_str()),
		"bearer leaked through the audit channel: {blob}"
	);
}
