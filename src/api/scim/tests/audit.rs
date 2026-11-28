//! The trace a SCIM write leaves: a password it sets and an account it
//! suspends or enables again are the same events the management route
//! writes, and a request that changed nothing writes none.
//!
//! The password, its hash and the bearer never reach the audit channel.

use axum::http::StatusCode;
use std::net::SocketAddr;

use crate::api::audit::tests::base::{audit_blob, audit_events, run_with_capture};

use super::base::{SCIM_KEY_SECRET, app, build_state, send, send_from};

/// The password the fixture sets. Distinctive, so the assertions on the
/// audit blob are about this one.
const PASSWORD: &str = "Scim-Rotated-Password-9";

/// A different one, for the writes that change the password.
const OTHER_PASSWORD: &str = "Scim-Second-Password-7";

/// The kinds of the lines the capture took, in order.
fn kinds(events: &[crate::api::audit::tests::base::CapturedEvent]) -> Vec<String> {
	audit_events(events)
		.iter()
		.map(|event| event.fields.get("event").cloned().unwrap_or_default())
		.collect()
}

/// Creating an account with a password writes one `account.password_reset`,
/// the event the management route writes for the same change.
#[tokio::test(flavor = "multi_thread")]
async fn creating_a_user_with_a_password_writes_one_line() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});

	let events = run_with_capture(async {
		let (status, body) = send(
			&app,
			"POST",
			"/scim/v2/Users",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&create),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{body}");
	});

	assert_eq!(kinds(&events), ["account.password_reset"], "{events:?}");
	let audit = audit_events(&events);
	assert_eq!(
		audit[0].fields.get("account").map(String::as_str),
		Some(crate::log_id::account("alice").as_str())
	);
	assert_eq!(
		audit[0].fields.get("client_ip").map(String::as_str),
		Some("unknown")
	);

	let blob = audit_blob(&events);
	assert!(
		!blob.contains(PASSWORD),
		"the audit carried the password: {blob}"
	);
	assert!(
		!blob.contains("$argon2id$"),
		"the audit carried the hash: {blob}"
	);
	assert!(
		!blob.contains(SCIM_KEY_SECRET.as_str()),
		"the audit leaked the bearer: {blob}"
	);
}

/// An account born suspended writes `account.disabled`.
#[tokio::test(flavor = "multi_thread")]
async fn creating_a_suspended_user_writes_one_line() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": false,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});

	let events = run_with_capture(async {
		let (status, body) = send(
			&app,
			"POST",
			"/scim/v2/Users",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&create),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{body}");
	});

	assert_eq!(
		kinds(&events),
		["account.password_reset", "account.disabled"],
		"{events:?}"
	);
	// The suspension line names the account and the key that asked, the way
	// the management route writes it.
	let audit = audit_events(&events);
	assert_eq!(
		audit[1].fields.get("account").map(String::as_str),
		Some(crate::log_id::account("alice").as_str())
	);
	assert_eq!(
		audit[1].fields.get("key").map(String::as_str),
		Some("scim"),
		"the label of the key, never the key"
	);
	assert_eq!(
		audit[1].fields.get("client_ip").map(String::as_str),
		Some("unknown")
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(SCIM_KEY_SECRET.as_str()),
		"the audit leaked the bearer: {blob}"
	);
}

/// A request that was refused writes nothing: there was no change to
/// record.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_creation_writes_no_line() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});

	let events = run_with_capture(async {
		let (status, _) = send(
			&app,
			"POST",
			"/scim/v2/Users",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&create),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED);
		// The same name again: the account exists already.
		let (status, body) = send(
			&app,
			"POST",
			"/scim/v2/Users",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&create),
		)
		.await;
		assert_eq!(status, StatusCode::CONFLICT, "{body}");
	});

	// Only the first, accepted, request left a trace.
	assert_eq!(kinds(&events), ["account.password_reset"], "{events:?}");
}

/// A `PATCH` that sets the password writes `account.password_reset`, and one
/// that suspends the account writes `account.disabled`.
#[tokio::test(flavor = "multi_thread")]
async fn a_patch_writes_the_line_of_every_change_it_makes() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let events = run_with_capture(async {
		let patch = serde_json::json!({
			"Operations": [
				{"op": "replace", "path": "password", "value": OTHER_PASSWORD},
				{"op": "replace", "path": "active", "value": false}
			]
		});
		let (status, body) = send(
			&app,
			"PATCH",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&patch),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	assert_eq!(
		kinds(&events),
		["account.password_reset", "account.disabled"],
		"{events:?}"
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(OTHER_PASSWORD),
		"the audit carried the password: {blob}"
	);
	assert!(
		!blob.contains("$argon2id$"),
		"the audit carried the hash: {blob}"
	);
}

/// A `PATCH` that asks for the account as it is writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_patch_that_changes_nothing_writes_no_line() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let events = run_with_capture(async {
		// The account is active: asking for it to be active changes nothing.
		let patch = serde_json::json!({
			"Operations": [{"op": "replace", "path": "active", "value": true}]
		});
		let (status, body) = send(
			&app,
			"PATCH",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&patch),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	assert!(
		audit_events(&events).is_empty(),
		"a patch that changed nothing wrote a line: {events:?}"
	);
}

/// A `PUT` writes the line of every change it makes: the password it sets
/// and the state it leaves the account in.
#[tokio::test(flavor = "multi_thread")]
async fn a_put_writes_the_line_of_every_change_it_makes() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let events = run_with_capture(async {
		let replace = serde_json::json!({
			"userName": "alice",
			"active": false,
			"emails": [{"value": "alice@example.org"}],
			"password": OTHER_PASSWORD
		});
		let (status, body) = send(
			&app,
			"PUT",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&replace),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	assert_eq!(
		kinds(&events),
		["account.password_reset", "account.disabled"],
		"{events:?}"
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(OTHER_PASSWORD),
		"the audit carried the password: {blob}"
	);
}

/// A `PUT` that was refused writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_put_writes_no_line() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let events = run_with_capture(async {
		// The name cannot be changed: the request is refused before
		// anything is written.
		let replace = serde_json::json!({
			"userName": "mallory",
			"active": false,
			"emails": [{"value": "alice@example.org"}],
			"password": OTHER_PASSWORD
		});
		let (status, body) = send(
			&app,
			"PUT",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&replace),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	});

	assert!(
		audit_events(&events).is_empty(),
		"a refused put wrote a line: {events:?}"
	);
}

/// An account that is enabled again writes `account.enabled`.
#[tokio::test(flavor = "multi_thread")]
async fn enabling_an_account_again_writes_one_line() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": false,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let events = run_with_capture(async {
		let patch = serde_json::json!({
			"Operations": [{"op": "replace", "path": "active", "value": true}]
		});
		let (status, body) = send(
			&app,
			"PATCH",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&patch),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	assert_eq!(kinds(&events), ["account.enabled"], "{events:?}");
}

/// The line of a password reset says which key made it: the label of the
/// key, never the key.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_reset_names_the_key_that_made_it() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let events = run_with_capture(async {
		let patch = serde_json::json!({
			"Operations": [
				{"op": "replace", "path": "password", "value": OTHER_PASSWORD}
			]
		});
		let (status, body) = send(
			&app,
			"PATCH",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&patch),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	assert_eq!(kinds(&events), ["account.password_reset"], "{events:?}");
	let audit = audit_events(&events);
	assert_eq!(
		audit[0].fields.get("key").map(String::as_str),
		Some("scim"),
		"the label of the key that asked, never the key"
	);
	let blob = audit_blob(&events);
	assert!(
		!blob.contains(SCIM_KEY_SECRET.as_str()),
		"the audit leaked the bearer: {blob}"
	);
}

/// The lines of a deletion carry the address the request came from, the
/// same way the management route writes them.
#[tokio::test(flavor = "multi_thread")]
async fn a_deletion_carries_the_client_that_asked() {
	let (_dir, state) = build_state();
	let app = app(state);
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": PASSWORD
	});
	let (status, body) = send(
		&app,
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");

	let peer: SocketAddr = "203.0.113.11:40000".parse().expect("peer");
	let events = run_with_capture(async {
		let (status, body) = send_from(
			&app,
			"DELETE",
			"/scim/v2/Users/alice",
			Some(SCIM_KEY_SECRET.as_str()),
			None,
			peer,
		)
		.await;
		assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
	});

	// SCIM writes the privilege line and the one with the counts: both name
	// the client that asked.
	let lines = audit_events(&events);
	assert_eq!(lines.len(), 2, "{events:?}");
	for line in lines {
		assert_eq!(
			line.fields.get("client_ip").map(String::as_str),
			Some("203.0.113.11"),
			"the line names the client that asked: {line:?}"
		);
	}
}
