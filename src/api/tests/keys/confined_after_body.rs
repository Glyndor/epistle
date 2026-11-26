//! The reach of a key is asked about again when a request's body is complete,
//! including whether the key is now bound to an account and whether that
//! account is still live.

use axum::http::StatusCode;
use serde_json::json;

use super::super::base::{TOKEN, request, test_state};
use super::super::jmap_email::jmap_disabled::slow_request;
use super::*;
use crate::directory_store::DynamicAccount;

const SECRET: &str = "confined-after-body-secret";

/// A server with the dynamic account `dyna` and one key, `k`, with `scopes`
/// and bound to `account`.
fn state_with(
	dir: &std::path::Path,
	scopes: &[&str],
	account: Option<&str>,
) -> crate::api::ApiState {
	let state = test_state(dir, 0);
	state
		.store()
		.add(DynamicAccount {
			name: "dyna".to_string(),
			addresses: vec!["dyna@example.org".to_string()],
			password_hash: "$argon2id$prior".to_string(),
			..DynamicAccount::default()
		})
		.expect("add dyna");
	put_key(&state, dir, scopes, account);
	state
}

/// Write the key `k` with `scopes` and `account`, and reload the key set as the
/// watcher does.
fn put_key(
	state: &crate::api::ApiState,
	dir: &std::path::Path,
	scopes: &[&str],
	account: Option<&str>,
) {
	let mut store = crate::api::ApiKeyStore::open(dir).expect("key store");
	let _ = store.remove("k");
	store
		.add(crate::api::api_keys::ApiKey {
			label: "k".to_string(),
			hash: crate::api::api_keys::sha256_hash(SECRET),
			expires_at: None,
			ip_cidr: None,
			scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
			grants: Vec::new(),
			domains: Vec::new(),
			account: account.map(str::to_string),
			auto_submitted: false,
		})
		.expect("add key");
	let text = std::fs::read_to_string(dir.join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
}

fn password_hash(state: &crate::api::ApiState) -> String {
	state
		.store()
		.dynamic_account("dyna")
		.expect("dyna")
		.password_hash
}

#[tokio::test]
async fn a_key_bound_to_an_account_while_the_body_arrives_leaves_the_administrative_routes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with(dir.path(), &["manage:write"], None);
	let app = router(state.clone());
	let body = || json!({ "password": crate::test_support::fixtures::second_password() });
	let before = password_hash(&state);
	let (status, answer) = slow_request(
		&app,
		"PUT",
		"/api/v1/accounts/dyna/password",
		SECRET,
		body(),
		|| put_key(&state, dir.path(), &["manage:write"], Some("dyna")),
	)
	.await;
	assert!(!status.is_success(), "{status}: {answer}");
	assert_eq!(
		password_hash(&state),
		before,
		"the password was not touched"
	);
}

#[tokio::test]
async fn suspending_the_account_of_a_bound_key_while_the_body_arrives_stops_the_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with(dir.path(), &["mail:write"], Some("dyna"));
	let app = router(state.clone());
	let path = "/api/v1/suppression?account=dyna";
	// Control: nothing changes while the body arrives, and it is served.
	let (status, answer) = slow_request(
		&app,
		"POST",
		path,
		SECRET,
		json!({ "address": "kept@example.net" }),
		|| {},
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{answer}");
	let (status, answer) = slow_request(
		&app,
		"POST",
		path,
		SECRET,
		json!({ "address": "late@example.net" }),
		|| {
			state.store().set_disabled("dyna", true).expect("disable");
		},
	)
	.await;
	assert!(!status.is_success(), "{status}: {answer}");
	let (status, listed) = request(&app, "GET", path, Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK, "{listed}");
	let listed = listed.to_string();
	assert!(listed.contains("kept@example.net"), "{listed}");
	assert!(!listed.contains("late@example.net"), "{listed}");
}
