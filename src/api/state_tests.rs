//! Tests for bearer-token plus API-key authorization on the management API.

use super::*;
use crate::api::api_keys::{ApiKey, ApiKeyStore};

fn ip(text: &str) -> std::net::IpAddr {
	text.parse().expect("ip")
}

/// Build a state whose configured token is `sha256(token)` and whose API-key
/// store (under `dir`) holds `keys`.
fn state_with_keys(dir: &std::path::Path, token: &str, keys: Vec<ApiKey>) -> ApiState {
	let mut store = ApiKeyStore::open(dir).expect("open key store");
	for key in keys {
		store.add(key).expect("add key");
	}
	let spool = crate::storage::FsSpool::open(dir).expect("spool");
	let accounts = crate::directory_store::AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("account store");
	ApiState::new(
		&crate::api::api_keys::sha256_hash(token),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		std::sync::Arc::new(accounts),
		spool,
	)
}

fn key(label: &str, secret: &str) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
	}
}

#[test]
fn configured_token_still_authorizes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", Vec::new());
	assert!(state.authorizes("the-token", None));
	assert!(!state.authorizes("wrong-token", None));
}

#[test]
fn valid_api_key_authorizes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", vec![key("ci", "key-secret")]);
	assert!(state.authorizes("key-secret", None));
	// The configured token also still works.
	assert!(state.authorizes("the-token", None));
}

#[test]
fn wrong_api_key_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", vec![key("ci", "key-secret")]);
	assert!(!state.authorizes("not-the-key", None));
}

#[test]
fn expired_api_key_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut expired = key("ci", "key-secret");
	expired.expires_at = Some(1); // long past
	let state = state_with_keys(dir.path(), "the-token", vec![expired]);
	assert!(!state.authorizes("key-secret", None));
}

#[test]
fn ip_restricted_api_key_enforced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut restricted = key("ci", "key-secret");
	restricted.ip_cidr = Some("10.0.0.0/8".to_string());
	let state = state_with_keys(dir.path(), "the-token", vec![restricted]);
	assert!(state.authorizes("key-secret", Some(ip("10.1.2.3"))));
	assert!(!state.authorizes("key-secret", Some(ip("192.0.2.1"))));
	// A restricted key with no known client IP cannot be satisfied.
	assert!(!state.authorizes("key-secret", None));
}
