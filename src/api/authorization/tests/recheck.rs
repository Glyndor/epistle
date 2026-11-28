//! The question a write asks under its lock, clause by clause: the scope and
//! the absence of any confinement, of the key as it is read then.

use super::*;
use crate::api::ApiState;
use crate::api::state::MatchedAuth;

const SECRET: &str = "recheck-unit-secret";

/// A server with one key, `k`, holding `scopes` and confined to `domains`.
fn state_with(dir: &std::path::Path, scopes: &[&str], domains: &[&str]) -> ApiState {
	let state = crate::api::tests::base::test_state(dir, 0);
	let mut store = crate::api::ApiKeyStore::open(dir).expect("key store");
	store
		.add(ApiKey {
			label: "k".to_string(),
			hash: crate::api::api_keys::sha256_hash(SECRET),
			expires_at: None,
			ip_cidr: None,
			scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
			grants: Vec::new(),
			domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
			account: None,
			auto_submitted: false,
		})
		.expect("add key");
	let text = std::fs::read_to_string(dir.join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
	state
}

/// A request admitted under either management scope, so that the scope asked
/// for is not already decided by what admitted it.
fn admitted() -> MatchedAuth {
	MatchedAuth {
		token: Some(SECRET.to_string()),
		client_ip: None,
		configured: false,
		acceptable_scopes: vec![Scope::ManageRead, Scope::ManageWrite],
		account_scoped: false,
	}
}

#[test]
fn only_a_key_with_the_scope_and_no_confinement_is_unrestricted_for_it() {
	let ask = |scopes: &[&str], domains: &[&str], scope: Scope| {
		let dir = tempfile::tempdir().expect("tempdir");
		let state = state_with(dir.path(), scopes, domains);
		Principal::still_unrestricted(&state, &admitted(), scope)
	};
	assert!(ask(&["manage:write"], &[], Scope::ManageWrite));
	assert!(ask(&["manage:read"], &[], Scope::ManageRead));
	assert!(!ask(&["manage:read"], &[], Scope::ManageWrite));
	assert!(!ask(
		&["manage:write"],
		&["example.org"],
		Scope::ManageWrite
	));
}
