//! A client that opens a stream and then stops reading: the server keeps no
//! state for it, and the socket it closes leaves no stream behind.

use std::time::Duration;

use super::base::{LIVE, READ_KEY, Stream, client, open, open_when_free, peer, state};
use crate::api::tests::hostile_wire::{read, supervised};
use axum::http::StatusCode;

/// The most streams one caller may hold open at once.
const MAX: usize = crate::api::jmap::event_source::MAX_STREAMS_PER_CALLER;

#[tokio::test]
async fn a_client_that_stops_reading_leaves_no_stream_behind() {
	if supervised(
		module_path!(),
		"a_client_that_stops_reading_leaves_no_stream_behind",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	// Open a stream and never read it: the server writes into the socket
	// and the client ignores every byte.
	let response = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
	assert_eq!(response.status(), StatusCode::OK);
	let stream = Stream::new(response);
	// The stream stays open while the client ignores it, so the server does
	// write into the socket nobody reads.
	tokio::time::sleep(Duration::from_millis(1500)).await;
	// The socket is closed now. The server notices on its next write and
	// gives the slot back.
	drop(stream);
	let mut held = Vec::new();
	for _ in 0..MAX {
		let response = open_when_free(
			&client,
			&peer.base,
			READ_KEY.as_str(),
			LIVE,
			Duration::from_secs(10),
		)
		.await;
		assert_eq!(response.status(), StatusCode::OK);
		held.push(Stream::new(response));
	}
	// The caller holds the whole cap and no more: the closed socket left
	// no stream behind.
	let refused = open(&client, &peer.base, Some(READ_KEY.as_str()), LIVE).await;
	assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
	let (status, body) = read(refused).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(body["limit"], "maxConcurrentEventSources", "{body}");
	// The server is still serving: the streams it holds still ping.
	for stream in held.iter_mut() {
		let (name, _) = stream
			.next_event_within(Duration::from_secs(5))
			.await
			.expect("the server keeps serving the streams it holds");
		assert_eq!(name, "ping");
	}
	peer.healthy().await;
}
