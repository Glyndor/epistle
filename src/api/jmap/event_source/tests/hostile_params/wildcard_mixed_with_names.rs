//! A `types` value that mixes the wildcard with names is neither the
//! single character `*` nor a list of type names, so the route must refuse
//! it.
//!
//! RFC 8620 §7.3: the `types` variable "MUST be either a comma-separated
//! list of type names" or "the single character: `*`". The module's own
//! contract says the same: "`types`: `*` or a comma-separated list".
//!
//! `types=*,Email` used to open a stream that pushed only `Email`: the client
//! asked for every type and silently stopped receiving the ones it did not
//! name.

use super::super::base::{READ_KEY, client, open, peer, state};
use crate::api::tests::hostile_wire::{read, supervised};
use axum::http::StatusCode;

#[tokio::test]
async fn a_types_filter_that_mixes_the_wildcard_with_names_is_refused() {
	if supervised(
		module_path!(),
		"a_types_filter_that_mixes_the_wildcard_with_names_is_refused",
	) {
		return;
	}
	let dir = tempfile::tempdir().expect("tempdir");
	let peer = peer(state(dir.path())).await;
	let client = client();
	let response = open(
		&client,
		&peer.base,
		Some(READ_KEY.as_str()),
		"types=*,Email&closeafter=no&ping=0",
	)
	.await;
	assert_eq!(
		response.status(),
		StatusCode::BAD_REQUEST,
		"a types value that is neither \"*\" nor a list of names must be refused"
	);
	let (status, body) = read(response).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:invalidArguments");
	assert!(
		body["detail"]
			.as_str()
			.is_some_and(|detail| !detail.is_empty()),
		"{body}"
	);
	peer.healthy().await;
}
