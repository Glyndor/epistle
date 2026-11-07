//! The suppression lists the operator keeps entries on.

use super::base::{TOKEN, request, test_state};
use super::*;
use axum::http::StatusCode;

#[tokio::test]
async fn suppression_lists_global_and_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("open");
	suppression.suppress("bob@example.net");
	suppression.suppress_for("alice@example.org", "carol@example.net");
	let app = router(test_state(dir.path(), 0));

	// Global list.
	let (status, body) = request(&app, "GET", "/api/v1/suppression", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "bob@example.net");

	// Per-account list.
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=alice@example.org",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "carol@example.net");
}

#[tokio::test]
async fn suppression_delete_removes_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("open");
	suppression.suppress("bob@example.net");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/suppression/bob@example.net",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["removed"], "bob@example.net");
	assert!(
		!crate::queue::SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}
