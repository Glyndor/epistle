//! A stream ends when the credential that opened it stops holding.

use std::time::Duration;

use axum::http::StatusCode;

use super::base::{ADMIN, SOON, TENANT_A, app, fast, open, settle, state, stream};
use crate::api::ApiKeyStore;
use crate::api::EventLimits;

/// Rewrite the key file the way the CLI does and make the server read it.
fn reload(
	state: &crate::api::ApiState,
	dir: &std::path::Path,
	edit: impl FnOnce(&mut ApiKeyStore),
) {
	let mut keys = ApiKeyStore::open(dir).expect("key store");
	edit(&mut keys);
	drop(keys);
	let text = std::fs::read_to_string(dir.join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
}

#[tokio::test]
async fn a_revoked_key_is_cut() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	let mut tenant = stream(&app, TENANT_A, None).await;
	settle().await;
	reload(&state, dir.path(), |keys| {
		keys.remove("admin").expect("remove")
	});
	assert!(
		admin.ends_within(SOON).await,
		"the stream outlived its revoked key"
	);
	// A key that was not revoked goes on.
	assert!(!tenant.ends_within(Duration::from_millis(400)).await);
	// And the revoked one cannot open another.
	assert_eq!(
		open(&app, Some(ADMIN), None).await.status,
		StatusCode::UNAUTHORIZED
	);
	// The slot came back.
	assert_eq!(state.events().open_streams(), 1);
}

#[tokio::test]
async fn a_key_that_loses_read_is_cut() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	settle().await;
	reload(&state, dir.path(), |keys| {
		let hash = keys.hash_of("admin").expect("hash");
		keys.remove("admin").expect("remove");
		keys.add(crate::api::ApiKey {
			grants: Vec::new(),
			label: "admin".to_string(),
			hash,
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["write".to_string()],
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
		})
		.expect("add");
	});
	assert!(
		admin.ends_within(SOON).await,
		"the stream kept read it lost"
	);
}

#[tokio::test]
async fn a_key_confined_after_opening_is_cut() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	settle().await;
	reload(&state, dir.path(), |keys| {
		let hash = keys.hash_of("admin").expect("hash");
		keys.remove("admin").expect("remove");
		keys.add(crate::api::ApiKey {
			grants: Vec::new(),
			label: "admin".to_string(),
			hash,
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: vec!["a.example".to_string()],
			account: None,
			auto_submitted: false,
		})
		.expect("add");
	});
	assert!(
		admin.ends_within(SOON).await,
		"a stream opened unconfined went on after the key was confined"
	);
}

#[tokio::test]
async fn a_stream_ends_after_its_lifetime() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(
		dir.path(),
		EventLimits {
			max_lifetime: Duration::from_millis(300),
			..fast()
		},
	);
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	assert!(admin.ends_within(SOON).await, "the stream never ended");
	assert_eq!(state.events().open_streams(), 0);
}
