//! The caps on open streams, and that nothing runs while nobody listens.

use std::time::Duration;

use axum::http::{StatusCode, header};

use super::base::{ADMIN, SOON, TENANT_A, TENANT_B, app, fast, open, state, stream};
use crate::api::EventLimits;

#[tokio::test]
async fn one_key_holds_a_bounded_number_of_streams() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(
		dir.path(),
		EventLimits {
			per_key: 2,
			..fast()
		},
	);
	let app = app(&state);
	let first = stream(&app, ADMIN, None).await;
	let _second = stream(&app, ADMIN, None).await;
	let refused = open(&app, Some(ADMIN), None).await;
	assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(
		refused.headers[header::CONTENT_TYPE],
		"application/problem+json"
	);
	assert!(refused.headers.contains_key(header::RETRY_AFTER));
	let bytes = axum::body::to_bytes(refused.body, 1 << 20)
		.await
		.expect("body");
	let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem");
	assert_eq!(problem["code"], "rate_limited", "{problem}");
	// Another key has its own count.
	let _other = stream(&app, TENANT_A, None).await;
	// Closing one gives the slot back.
	drop(first);
	assert_eq!(
		open(&app, Some(ADMIN), None).await.status,
		StatusCode::OK,
		"the slot of a closed stream is free again"
	);
}

#[tokio::test]
async fn the_server_holds_a_bounded_number_of_streams() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(
		dir.path(),
		EventLimits {
			per_server: 2,
			..fast()
		},
	);
	let app = app(&state);
	let first = stream(&app, ADMIN, None).await;
	let _second = stream(&app, TENANT_A, None).await;
	assert_eq!(state.events().open_streams(), 2);
	let refused = open(&app, Some(TENANT_B), None).await;
	assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
	// A refusal by the server cap does not leave the key's slot taken.
	assert_eq!(state.events().open_streams(), 2);
	drop(first);
	assert_eq!(
		open(&app, Some(TENANT_B), None).await.status,
		StatusCode::OK
	);
}

#[tokio::test]
async fn nothing_samples_while_nobody_listens() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	assert!(!state.events().is_sampling());
	let reader = stream(&app, ADMIN, None).await;
	assert!(state.events().is_sampling());
	drop(reader);
	let deadline = tokio::time::Instant::now() + SOON;
	while state.events().is_sampling() {
		assert!(
			tokio::time::Instant::now() < deadline,
			"the sampler outlived the last stream"
		);
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert_eq!(state.events().open_streams(), 0);
}
