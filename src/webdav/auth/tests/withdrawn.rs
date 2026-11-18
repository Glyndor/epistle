//! WebDAV authenticates every request against the directory of that moment,
//! so the request after an account is disabled, or has its credentials
//! reset, is refused like an unknown login.

use super::*;
use crate::test_support::{accounts, fixtures};
use axum::http::HeaderValue;

fn basic(login: &str) -> HeaderMap {
	use base64::Engine;
	let encoded = base64::engine::general_purpose::STANDARD
		.encode(format!("{login}:{}", fixtures::password()));
	let mut headers = HeaderMap::new();
	headers.insert(
		AUTHORIZATION,
		HeaderValue::from_str(&format!("Basic {encoded}")).expect("header"),
	);
	headers
}

#[test]
fn the_request_after_the_account_is_disabled_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let handle = store.handle();
	assert_eq!(
		authenticate(&basic("alice"), &handle, None).as_deref(),
		Some("alice")
	);
	accounts::disable(&store, "alice");
	assert_eq!(authenticate(&basic("alice"), &handle, None), None);
	assert_eq!(
		authenticate(&basic("bob"), &handle, None).as_deref(),
		Some("bob")
	);
}

#[test]
fn the_request_after_a_credential_reset_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let handle = store.handle();
	assert_eq!(
		authenticate(&basic("alice"), &handle, None).as_deref(),
		Some("alice")
	);
	accounts::reset(&store, "alice");
	assert_eq!(authenticate(&basic("alice"), &handle, None), None);
	assert_eq!(
		authenticate(&basic("bob"), &handle, None).as_deref(),
		Some("bob")
	);
}
