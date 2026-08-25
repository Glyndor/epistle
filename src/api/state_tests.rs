//! Tests for bearer-token plus API-key authorization on the management API.

use super::*;
use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope};

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
		// `add()` rejects empty scopes; every test-built key carries one.
		scopes: vec![Scope::Read.as_str().to_string()],
	}
}

#[test]
fn configured_token_still_authorizes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", Vec::new());
	assert!(state.authorizes("the-token", None, &[Scope::Read]));
	assert!(!state.authorizes("wrong-token", None, &[Scope::Read]));
}

#[test]
fn valid_api_key_authorizes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", vec![key("ci", "key-secret")]);
	assert!(state.authorizes("key-secret", None, &[Scope::Read]));
	// The configured token also still works.
	assert!(state.authorizes("the-token", None, &[Scope::Read]));
}

#[test]
fn wrong_api_key_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", vec![key("ci", "key-secret")]);
	assert!(!state.authorizes("not-the-key", None, &[Scope::Read]));
}

#[test]
fn expired_api_key_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut expired = key("ci", "key-secret");
	expired.expires_at = Some(1); // long past
	let state = state_with_keys(dir.path(), "the-token", vec![expired]);
	assert!(!state.authorizes("key-secret", None, &[Scope::Read]));
}

#[test]
fn ip_restricted_api_key_enforced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut restricted = key("ci", "key-secret");
	restricted.ip_cidr = Some("10.0.0.0/8".to_string());
	let state = state_with_keys(dir.path(), "the-token", vec![restricted]);
	assert!(state.authorizes("key-secret", Some(ip("10.1.2.3")), &[Scope::Read]));
	assert!(!state.authorizes("key-secret", Some(ip("192.0.2.1")), &[Scope::Read]));
	// A restricted key with no known client IP cannot be satisfied.
	assert!(!state.authorizes("key-secret", None, &[Scope::Read]));
}

/// `owns_address` must return `false` when no directory has been attached
/// (fail-closed). Without this guarantee, a future deployment that forgets
/// to wire the directory would silently allow every send-as.
#[test]
fn owns_address_is_fail_closed_without_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_keys(dir.path(), "the-token", Vec::new());
	let address =
		crate::smtp::address::Address::parse("alice@example.org").expect("address parses");
	// No directory attached: every owns_address call is `false`, even for an
	// address that *would* be owned if the directory were wired up.
	assert!(
		!state.owns_address("alice", &address),
		"owns_address must fail closed when no directory is attached"
	);
}

/// `owns_address` delegates to the wired-in directory: a foreign address is
/// rejected, an owned one is accepted, and a case-different variant of an
/// owned address is still accepted (Directory::owns_address is
/// case-insensitive on the address — see src/smtp/directory.rs:412).
#[test]
fn owns_address_consults_attached_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let accounts = crate::config::Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
	};
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![accounts],
		)
		.expect("open store"),
	);
	let state = state_with_keys(dir.path(), "the-token", Vec::new()).with_directory(store.handle());
	let owned = crate::smtp::address::Address::parse("alice@example.org").expect("address parses");
	let foreign = crate::smtp::address::Address::parse("bob@example.org").expect("address parses");
	let case_variant =
		crate::smtp::address::Address::parse("ALICE@example.ORG").expect("address parses");
	assert!(state.owns_address("alice", &owned));
	assert!(!state.owns_address("alice", &foreign));
	assert!(state.owns_address("alice", &case_variant));
}
