//! The account lifecycle the REST surface drives: create, password,
//! second factor and delete.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use crate::test_support::fixtures;
use axum::http::StatusCode;

// --- Account management: the write surface (requires the `write` scope) -------

/// The account CRUD + password flow: a `write` scope is what unlocks it.
#[tokio::test]
async fn account_create_delete_and_password_flow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@example.org"],
			"password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"API response must have the expected status or field"
	);
	assert_eq!(body["created"], "bob");

	let (_, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	let names: Vec<&str> = body["accounts"]
		.as_array()
		.expect("accounts")
		.iter()
		.map(|account| account["name"].as_str().expect("name"))
		.collect();
	assert!(
		names.contains(&"bob"),
		"API response must have the expected status or field"
	);

	let (status, _) = request_with_body(
		&app,
		"PUT",
		"/api/v1/accounts/bob/password",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({"password": fixtures::second_password()})),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/bob?queue=drain",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"API response must have the expected status or field"
	);

	// Static accounts cannot be deleted.
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/alice?queue=drain",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

/// TOTP enrollment is part of the account write surface: a `write` scope is
/// what unlocks the secret issuance and revocation endpoints.
#[tokio::test]
async fn totp_enrollment_stores_a_valid_secret() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob", "addresses": ["bob@example.org"], "password": fixtures::password()
		})),
	)
	.await;

	let (status, body) = request(
		&app,
		"POST",
		"/api/v1/accounts/bob/totp",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"API response must have the expected status or field"
	);
	let secret = body["secret"].as_str().expect("secret");
	// A valid base32 TOTP secret that decodes.
	super::secret_diagnostics::assert_totp_secret(secret);
	assert!(
		body["otpauth_uri"]
			.as_str()
			.unwrap_or("")
			.contains("otpauth://totp/"),
		"API response must have the expected status or field"
	);

	// Disabling clears it.
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/bob/totp",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

/// Account creation rejects weak / over-long / foreign-domain / duplicate
/// inputs at the edge — the same place the `write` scope is checked.
#[tokio::test]
async fn account_creation_validates_input() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	// Short password.
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob", "addresses": ["bob@example.org"], "password": "short"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);

	// Over-long password (>64 chars): the DoS ceiling rejects it.
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob", "addresses": ["bob@example.org"], "password": "x".repeat(65)
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"]["code"], "invalid_input");

	// Foreign domain.
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob", "addresses": ["bob@elsewhere.example"], "password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);

	// Duplicate static name.
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "alice", "addresses": ["alice2@example.org"], "password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The deletion endpoint must require `?queue=` so a misconfigured
/// client never silently drops queued mail. A missing parameter and an
/// unknown value are both `400 invalid_input`.
#[tokio::test]
async fn delete_without_a_queue_policy_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "harvey",
			"addresses": ["harvey@example.org"],
			"password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"API response must have the expected status or field"
	);

	// Missing parameter.
	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/harvey",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::BAD_REQUEST,
		"API response must have the expected status or field"
	);
	assert_eq!(body["error"]["code"], "invalid_input");

	// Unknown parameter value.
	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/harvey?queue=bogus",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::BAD_REQUEST,
		"API response must have the expected status or field"
	);
	assert_eq!(body["error"]["code"], "invalid_input");
}

/// The `discard` policy reports the per-record counts in the response
/// body so the caller can correlate what was removed (mailbox_files is
/// always at least the directory itself, plus every file walked).
#[tokio::test]
async fn delete_with_discard_reports_the_counts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "ivy",
			"addresses": ["ivy@example.org"],
			"password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"API response must have the expected status or field"
	);

	// Seed a mailbox message so `mailbox_files` is non-zero.
	let mailbox = dir.path().join("accounts/ivy/new");
	std::fs::create_dir_all(&mailbox).expect("mkdir");
	std::fs::write(mailbox.join("a.eml"), b"Subject: hi\r\n\r\nbody\r\n").expect("write");

	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/ivy?queue=discard",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"API response must have the expected status or field"
	);
	assert_eq!(body["removed"], "ivy");
	assert!(
		body["mailbox_files"].as_u64().unwrap_or(0) >= 1,
		"counts must surface the walked mailbox files: {body}"
	);
	assert_eq!(body["queued_messages_discarded"], 0);
	assert_eq!(body["queued_messages_left"], 0);
}
