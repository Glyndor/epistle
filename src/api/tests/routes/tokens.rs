//! The bearer token the API answers with.

use super::base::{TOKEN, request, sha256_hash, test_state};
use super::*;
use axum::http::StatusCode;
use std::time::Duration;

use crate::storage::FsSpool;

#[tokio::test]
async fn requests_without_token_are_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/status", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(body["error"]["code"], "unauthenticated");

	let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sha256_token_format_is_accepted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![],
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&sha256_hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		vec![],
		store.clone(),
		spool,
	)
	.with_directory(store.handle());
	let app = router(state);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_triggers_after_repeated_failures() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The wall clock under a loaded parallel run is not the thing under test
	// here; the limiter's window logic is covered by
	// `src/api/state/tests/limiter.rs`.
	// Stretch the window so the 21 calls cannot span it.
	let app = router(test_state(dir.path(), 0).with_auth_window(Duration::from_secs(3600)));
	for _ in 0..20 {
		let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
	}
	let (status, body) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(body["error"]["code"], "rate_limited");
}
