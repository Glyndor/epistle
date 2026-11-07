//! The routes every deployment answers, whatever it serves.

use super::base::{TOKEN, request, test_state};
use super::*;
use axum::http::StatusCode;

#[tokio::test]
async fn healthz_is_unauthenticated() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// Liveness probe needs no token.
	let (status, _) = request(&app, "GET", "/healthz", None).await;
	assert_eq!(status, StatusCode::OK);
	// The authenticated surface still rejects tokenless requests.
	let (status, _) = request(&app, "GET", "/api/v1/status", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_reports_counts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 2));
	let (status, body) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["domains"], 1);
	assert_eq!(body["accounts"], 1);
	assert_eq!(body["queue_size"], 2);
}

#[tokio::test]
async fn accounts_never_expose_credentials() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["accounts"][0]["name"], "alice");
	assert!(!body.to_string().contains("argon2"), "{body}");
}

#[tokio::test]
async fn domains_are_listed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/domains", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["domains"][0], "example.org");
}

#[tokio::test]
async fn a_disabled_domain_is_named_in_the_domain_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, body) = request(&app, "GET", "/api/v1/domains", Some(TOKEN.as_str())).await;
	assert_eq!(body["disabled"], serde_json::json!([]));
	let off = test_state(dir.path(), 0).with_disabled_domains(vec!["Example.ORG".to_string()]);
	let app = router(off);
	let (status, body) = request(&app, "GET", "/api/v1/domains", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["domains"][0], "example.org");
	assert_eq!(body["disabled"], serde_json::json!(["example.org"]));
}

#[tokio::test]
async fn unknown_route_is_404() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request(&app, "GET", "/api/v1/nope", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mailboxes_lists_inbox_for_known_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/mailboxes",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let mailboxes = body["mailboxes"].as_array().expect("mailboxes");
	assert!(mailboxes.iter().any(|m| m == "INBOX"), "{body}");
}

#[tokio::test]
async fn mailboxes_returns_404_for_unknown_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/nobody/mailboxes",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "not_found");
}
