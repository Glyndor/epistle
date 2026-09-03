use super::tests::{TOKEN, request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

// --- Scope enforcement on the bearer middleware ---------------------------------

/// A read-only API key authenticates against `GET /api/v1/status` (the coarse
/// middleware scope is `Read`): this is the acceptance half of the read-vs-
/// write control.
#[tokio::test]
async fn read_scoped_key_is_admitted_on_get() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "reader".to_string(),
			hash: crate::api::api_keys::sha256_hash("reader-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("reader-secret")).await;
	assert_eq!(status, StatusCode::OK, "read scope admits a GET");
}

/// A read-only API key is rejected on `POST /api/v1/send` (the coarse
/// middleware scope is `Send`): this is the rejection half of the send
/// blast-radius control. Without this guard a leaked `read` key would be
/// indistinguishable from a leaked configured token.
#[tokio::test]
async fn read_scoped_key_is_rejected_on_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "reader".to_string(),
			hash: crate::api::api_keys::sha256_hash("reader-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("reader-secret"),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED, "read scope must not send");
	assert_eq!(body["error"]["code"], "unauthenticated");
}

/// A send-only API key cannot write to `/api/v1/accounts` — scopes are
/// independent (a `send` key is not also a `write` key).
#[tokio::test]
async fn send_scoped_key_is_rejected_on_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "sender".to_string(),
			hash: crate::api::api_keys::sha256_hash("sender-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string()],
			domains: Vec::new(),
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some("sender-secret"),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@example.org"],
			"password": "a-long-password"
		})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"send scope must not mutate accounts"
	);
	assert_eq!(body["error"]["code"], "unauthenticated");
}

/// A send-only API key passes the middleware on `POST /api/v1/send`: the
/// acceptance half of the send blast-radius control.
#[tokio::test]
async fn send_scoped_key_is_admitted_on_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "sender".to_string(),
			hash: crate::api::api_keys::sha256_hash("sender-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string()],
			domains: Vec::new(),
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("sender-secret"),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "send scope admits a /send POST");
}

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
			"password": "a-long-password"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["created"], "bob");

	let (_, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	let names: Vec<&str> = body["accounts"]
		.as_array()
		.expect("accounts")
		.iter()
		.map(|account| account["name"].as_str().expect("name"))
		.collect();
	assert!(names.contains(&"bob"), "{body}");

	let (status, _) = request_with_body(
		&app,
		"PUT",
		"/api/v1/accounts/bob/password",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({"password": "another-long-password"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/bob?queue=drain",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");

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
			"name": "bob", "addresses": ["bob@example.org"], "password": "a-long-password"
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
	assert_eq!(status, StatusCode::OK, "{body}");
	let secret = body["secret"].as_str().expect("secret");
	// A valid base32 TOTP secret that decodes.
	assert!(
		crate::totp::decode_base32_secret(secret).is_some(),
		"{secret}"
	);
	assert!(
		body["otpauth_uri"]
			.as_str()
			.unwrap_or("")
			.contains("otpauth://totp/"),
		"{body}"
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
			"name": "bob", "addresses": ["bob@elsewhere.example"], "password": "a-long-password"
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
			"name": "alice", "addresses": ["alice2@example.org"], "password": "a-long-password"
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

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "harvey",
			"addresses": ["harvey@example.org"],
			"password": "a-long-password"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");

	// Missing parameter.
	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/harvey",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input");

	// Unknown parameter value.
	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/harvey?queue=bogus",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input");
}

/// The `discard` policy reports the per-record counts in the response
/// body so the caller can correlate what was removed (mailbox_files is
/// always at least the directory itself, plus every file walked).
#[tokio::test]
async fn delete_with_discard_reports_the_counts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "ivy",
			"addresses": ["ivy@example.org"],
			"password": "a-long-password"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");

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
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["removed"], "ivy");
	assert!(
		body["mailbox_files"].as_u64().unwrap_or(0) >= 1,
		"counts must surface the walked mailbox files: {body}"
	);
	assert_eq!(body["queued_messages_discarded"], 0);
	assert_eq!(body["queued_messages_left"], 0);
}
