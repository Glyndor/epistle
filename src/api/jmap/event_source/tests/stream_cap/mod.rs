//! One caller may hold four event-source streams: the fifth is refused with
//! the RFC 8620 limit problem, the four that were open keep running, and
//! closing one gives its slot back.

use std::time::Duration;

use super::base::{LIVE, READ_KEY, Stream, client, open, open_when_free, peer, state};
use crate::api::tests::hostile_wire::{read, supervised};
use axum::http::StatusCode;

/// The most streams one caller may hold open at once.
const MAX: usize = crate::api::jmap::event_source::MAX_STREAMS_PER_CALLER;

#[tokio::test]
async fn the_fifth_stream_is_refused_and_the_four_others_keep_running() {
	if supervised(
		module_path!(),
		"the_fifth_stream_is_refused_and_the_four_others_keep_running",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	let mut held = Vec::new();
	for _ in 0..MAX {
		let response = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
		assert_eq!(response.status(), StatusCode::OK);
		held.push(Stream::new(response));
	}
	// The fifth is refused, and the refusal names the limit it applied.
	let refused = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
	assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
	let (status, body) = read(refused).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit");
	assert_eq!(body["limit"], "maxConcurrentEventSources", "{body}");
	assert_eq!(body["status"], 429, "{body}");
	// The four that were open are still served: each one still pings.
	for stream in held.iter_mut() {
		let (name, data) = stream
			.next_event_within(Duration::from_secs(5))
			.await
			.expect("a refused stream leaves the other four running");
		assert_eq!(name, "ping");
		assert_eq!(data["interval"], 1);
	}
	// Closing one stream gives its slot back.
	drop(held.pop());
	let reopened = open_when_free(
		&client,
		&peer.base,
		READ_KEY.as_str(),
		LIVE,
		Duration::from_secs(10),
	)
	.await;
	assert_eq!(reopened.status(), StatusCode::OK);
	peer.healthy().await;
}
