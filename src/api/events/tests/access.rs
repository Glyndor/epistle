//! Who may open the stream, and how a refusal looks.

use axum::http::{StatusCode, header};

use super::base::{ADMIN, BOUND, TENANT_A, WRITE_ONLY, app, fast, open, state};

async fn body_json(body: axum::body::Body) -> serde_json::Value {
	let bytes = axum::body::to_bytes(body, 1 << 20).await.expect("body");
	serde_json::from_slice(&bytes).expect("problem JSON")
}

#[tokio::test]
async fn a_read_key_gets_an_event_stream() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(&state(dir.path(), fast()));
	for token in [ADMIN, TENANT_A] {
		let opened = open(&app, Some(token), None).await;
		assert_eq!(opened.status, StatusCode::OK);
		assert_eq!(
			opened.headers[header::CONTENT_TYPE],
			"text/event-stream",
			"{token}"
		);
		assert_eq!(opened.headers[header::CACHE_CONTROL], "no-cache");
		assert_eq!(opened.headers["x-accel-buffering"], "no");
	}
}

#[tokio::test]
async fn no_credential_is_a_problem_401() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(&state(dir.path(), fast()));
	let opened = open(&app, None, None).await;
	assert_eq!(opened.status, StatusCode::UNAUTHORIZED);
	assert_eq!(
		opened.headers[header::CONTENT_TYPE],
		"application/problem+json"
	);
	let problem = body_json(opened.body).await;
	assert_eq!(problem["status"], 401, "{problem}");
	assert_eq!(problem["code"], "unauthenticated", "{problem}");
	let wrong = open(&app, Some("not-a-key"), None).await;
	assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_key_without_read_is_a_problem_403() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(&state(dir.path(), fast()));
	let opened = open(&app, Some(WRITE_ONLY), None).await;
	assert_eq!(opened.status, StatusCode::FORBIDDEN);
	assert_eq!(
		opened.headers[header::CONTENT_TYPE],
		"application/problem+json"
	);
	let problem = body_json(opened.body).await;
	assert_eq!(problem["code"], "forbidden", "{problem}");
}

#[tokio::test]
async fn a_key_bound_to_one_account_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let opened = open(&app, Some(BOUND), None).await;
	assert_eq!(opened.status, StatusCode::FORBIDDEN);
	let problem = body_json(opened.body).await;
	assert_eq!(problem["code"], "forbidden", "{problem}");
	// A refusal takes no slot and starts nothing.
	assert_eq!(state.events().open_streams(), 0);
	assert!(!state.events().is_sampling());
}
