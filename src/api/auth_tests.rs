//! Tests for `/api/v1/auth/verify` — panel credential verification.
// codeql[rust/cleartext-storage-of-passwords] False positive: every literal password in this
// module is a test fixture (intentionally trivial strings, never real credentials);
// `create_account` and the request bodies only forward them as input to the system-under-test.

use axum::http::StatusCode;
use serde_json::json;

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};

async fn create_account(app: &axum::Router, name: &str, password: &str) {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN),
		Some(json!({
			"name": name,
			"addresses": [format!("{name}@example.org")],
			"password": password,
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn verify_flags_a_valid_admin() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_admins(vec!["ops".to_string()]));
	create_account(&app, "ops", "a-long-password").await;

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN),
		Some(json!({"name": "ops@example.org", "password": "a-long-password"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["valid"], true);
	assert_eq!(body["admin"], true);
}

#[tokio::test]
async fn verify_accepts_a_valid_non_admin_without_admin() {
	let dir = tempfile::tempdir().expect("tempdir");
	// No admins configured: a valid account is a user, never an admin.
	let app = router(test_state(dir.path(), 0));
	create_account(&app, "user", "a-long-password").await;

	let (_, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN),
		Some(json!({"name": "user@example.org", "password": "a-long-password"})),
	)
	.await;
	assert_eq!(body["valid"], true);
	assert_eq!(body["admin"], false);
}

#[tokio::test]
async fn verify_rejects_wrong_password_and_unknown_account_identically() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_admins(vec!["ops".to_string()]));
	create_account(&app, "ops", "a-long-password").await;

	// Wrong password for a real (admin) account.
	let (_, wrong) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN),
		Some(json!({"name": "ops@example.org", "password": "not-the-password"})),
	)
	.await;
	assert_eq!(wrong["valid"], false);
	assert_eq!(
		wrong["admin"], false,
		"admin must never leak on a bad password"
	);

	// Unknown account — indistinguishable from the wrong-password case.
	let (_, unknown) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN),
		Some(json!({"name": "ghost@example.org", "password": "a-long-password"})),
	)
	.await;
	assert_eq!(unknown, wrong);
}

#[tokio::test]
async fn verify_requires_the_bearer_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		None,
		Some(json!({"name": "x@example.org", "password": "a-long-password"})),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}
