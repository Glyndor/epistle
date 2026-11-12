//! The credentials the route refuses: none at all, and one that does not
//! carry the `read` scope a stream needs.

use super::base::{LIVE, READ_KEY, Stream, WRITE_KEY, client, open, peer, state};
use crate::api::tests::hostile_wire::{read, supervised};
use axum::http::StatusCode;

/// The most streams one caller may hold open at once.
const MAX: usize = crate::api::jmap::event_source::MAX_STREAMS_PER_CALLER;

#[tokio::test]
async fn a_stream_without_a_credential_is_refused() {
	if supervised(module_path!(), "a_stream_without_a_credential_is_refused") {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	let response = open(&client, &peer.base, None, LIVE).await;
	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	let (status, body) = read(response).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(body["error"]["code"], "unauthenticated", "{body}");
	// A refused request takes no slot: the caller can still hold the cap.
	let mut held = Vec::new();
	for _ in 0..MAX {
		let response = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
		assert_eq!(response.status(), StatusCode::OK);
		held.push(Stream::new(response));
	}
	let refused = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
	assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
	peer.healthy().await;
}

#[tokio::test]
async fn a_stream_with_too_little_scope_is_refused() {
	if supervised(module_path!(), "a_stream_with_too_little_scope_is_refused") {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	// A key that may write but not read cannot open a stream.
	let response = open(&client, &peer.base, Some(WRITE_KEY.as_str()), LIVE).await;
	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let (status, body) = read(response).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(body["error"]["code"], "forbidden", "{body}");
	// The refused request took no slot either.
	let mut held = Vec::new();
	for _ in 0..MAX {
		let response = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
		assert_eq!(response.status(), StatusCode::OK);
		held.push(Stream::new(response));
	}
	let refused = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
	assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
	peer.healthy().await;
}

#[tokio::test]
async fn a_bearer_that_is_not_a_credential_is_refused() {
	if supervised(
		module_path!(),
		"a_bearer_that_is_not_a_credential_is_refused",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	let response = open(&client, &peer.base, Some("not-a-credential"), LIVE).await;
	assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	peer.healthy().await;
}
