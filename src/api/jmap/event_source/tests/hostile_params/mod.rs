//! The query a hostile client sends: a `ping` that is not a number, a
//! `types` filter that is not a list of names, and both at their extremes.

mod wildcard_mixed_with_names;

use std::time::Duration;

use super::base::{READ_KEY, Stream, client, open, peer, state};
use crate::api::tests::hostile_wire::{read, supervised};
use axum::http::StatusCode;

#[tokio::test]
async fn a_ping_that_is_not_a_number_is_refused() {
	if supervised(module_path!(), "a_ping_that_is_not_a_number_is_refused") {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	for ping in [
		"-1",
		"soon",
		"1.5",
		"",
		"99999999999999999999999999",
		"1 2",
		"0x10",
	] {
		let query = format!("types=*&closeafter=no&ping={ping}");
		let response = open(&client, &peer.base, Some(READ_KEY.as_str()), &query).await;
		assert_eq!(response.status(), StatusCode::BAD_REQUEST, "ping={ping}");
		let (status, body) = read(response).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "ping={ping}");
		assert_eq!(body["type"], "urn:ietf:params:jmap:error:invalidArguments");
		assert_eq!(body["status"], 400, "ping={ping}");
		assert!(
			body["detail"]
				.as_str()
				.is_some_and(|detail| !detail.is_empty()),
			"ping={ping}: {body}"
		);
	}
	peer.healthy().await;
}

#[tokio::test]
async fn a_types_filter_that_is_not_a_list_of_names_is_refused() {
	if supervised(
		module_path!(),
		"a_types_filter_that_is_not_a_list_of_names_is_refused",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	for types in ["", "Email,,Mailbox", ",Email", "Email,", ","] {
		let query = format!("types={types}&closeafter=no&ping=0");
		let response = open(&client, &peer.base, Some(READ_KEY.as_str()), &query).await;
		assert_eq!(response.status(), StatusCode::BAD_REQUEST, "types={types}");
		let (status, body) = read(response).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "types={types}");
		assert_eq!(body["type"], "urn:ietf:params:jmap:error:invalidArguments");
		assert!(
			body["detail"]
				.as_str()
				.is_some_and(|detail| !detail.is_empty()),
			"types={types}: {body}"
		);
	}
	peer.healthy().await;
}

#[tokio::test]
async fn a_closeafter_that_is_not_state_or_no_is_refused() {
	if supervised(
		module_path!(),
		"a_closeafter_that_is_not_state_or_no_is_refused",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	for closeafter in ["maybe", "", "STATE", "no "] {
		let query = format!("types=*&closeafter={closeafter}&ping=0");
		let response = open(&client, &peer.base, Some(READ_KEY.as_str()), &query).await;
		assert_eq!(
			response.status(),
			StatusCode::BAD_REQUEST,
			"closeafter={closeafter}"
		);
	}
	peer.healthy().await;
}

#[tokio::test]
async fn a_ping_of_zero_opens_a_stream_that_never_pings() {
	if supervised(
		module_path!(),
		"a_ping_of_zero_opens_a_stream_that_never_pings",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	// RFC 8620 §7.3: a ping of "0" means the server sends no ping events.
	let response = open(
		&client,
		&peer.base,
		Some(READ_KEY.as_str()),
		"types=*&closeafter=no&ping=0",
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	let mut stream = Stream::new(response);
	assert!(
		stream
			.next_event_within(Duration::from_millis(2500))
			.await
			.is_none(),
		"a ping of zero must not ping"
	);
	peer.healthy().await;
}

#[tokio::test]
async fn a_ping_over_the_maximum_is_clamped_and_never_floods_the_client() {
	if supervised(
		module_path!(),
		"a_ping_over_the_maximum_is_clamped_and_never_floods_the_client",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	// The interval is clamped to the maximum the server honours (300
	// seconds), so a hostile value cannot turn into a ping every second.
	let response = open(
		&client,
		&peer.base,
		Some(READ_KEY.as_str()),
		"types=*&closeafter=no&ping=99999",
	)
	.await;
	assert_eq!(response.status(), StatusCode::OK);
	let mut stream = Stream::new(response);
	assert!(
		stream
			.next_event_within(Duration::from_millis(2500))
			.await
			.is_none(),
		"a clamped ping must not ping every second"
	);
	peer.healthy().await;
}

#[tokio::test]
async fn a_types_filter_of_thousands_of_names_is_harmless() {
	if supervised(
		module_path!(),
		"a_types_filter_of_thousands_of_names_is_harmless",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	// A name the server does not know is accepted and never pushed, so a
	// list of thousands of them is legal: it must cost the server the
	// parsing of the query and nothing more.
	let names: Vec<String> = (0..5000).map(|n| format!("Type{n}")).collect();
	let query = format!("types={}&closeafter=no&ping=1", names.join(","));
	let response = open(&client, &peer.base, Some(READ_KEY.as_str()), &query).await;
	assert_eq!(response.status(), StatusCode::OK);
	let mut stream = Stream::new(response);
	let (name, data) = stream
		.next_event_within(Duration::from_secs(5))
		.await
		.expect("the stream still serves");
	assert_eq!(name, "ping");
	assert_eq!(data["interval"], 1);
	peer.healthy().await;
}
