//! `[auth] scram = false` through the REST and SCIM account paths: no
//! verifier is derived for a new account, and a password change drops the
//! one an account already has.

use super::base::{TOKEN, request_with_body};
use super::router;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::test_fixtures as fixtures;
use axum::http::StatusCode;

/// API state over a store with SCRAM off, holding `carol` with a verifier
/// derived while SCRAM was still on.
fn scram_off_state(dir: &std::path::Path) -> super::ApiState {
	let store = AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_scram_enabled(false);
	store
		.add(
			DynamicAccount::with_password(
				"carol".to_string(),
				vec!["carol@example.org".to_string()],
				fixtures::password(),
				&crate::password::Policy::ASCII_ONLY,
				true,
			)
			.expect("carol"),
		)
		.expect("add carol");
	let store = std::sync::Arc::new(store);
	super::ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		crate::storage::FsSpool::open(dir).expect("spool"),
	)
	.with_directory(store.handle())
}

fn has_verifier(state: &super::ApiState, name: &str) -> bool {
	state
		.store()
		.dynamic(name)
		.expect("account present")
		.scram
		.is_some()
}

#[tokio::test]
async fn rest_account_create_stores_no_verifier() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = scram_off_state(dir.path());
	let (status, body) = request_with_body(
		&router(state.clone()),
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@example.org"],
			"password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		!has_verifier(&state, "bob"),
		"REST create with scram = false must not store a verifier"
	);
}

#[tokio::test]
async fn rest_password_change_drops_the_verifier() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = scram_off_state(dir.path());
	assert!(has_verifier(&state, "carol"), "precondition");
	let (status, body) = request_with_body(
		&router(state.clone()),
		"PUT",
		"/api/v1/accounts/carol/password",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "password": fixtures::second_password() })),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		!has_verifier(&state, "carol"),
		"REST password change with scram = false must drop the verifier"
	);
}

#[tokio::test]
async fn scim_user_create_stores_no_verifier() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = scram_off_state(dir.path());
	let (status, body) = request_with_body(
		&router(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"userName": "dave",
			"active": true,
			"emails": [{"value": "dave@example.org"}],
			"password": "Correct-Horse-Battery-9"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert!(
		!has_verifier(&state, "dave"),
		"SCIM create with scram = false must not store a verifier"
	);
}

#[tokio::test]
async fn scim_password_patch_drops_the_verifier() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = scram_off_state(dir.path());
	assert!(has_verifier(&state, "carol"), "precondition");
	let (status, body) = request_with_body(
		&router(state.clone()),
		"PATCH",
		"/scim/v2/Users/carol",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"Operations": [{"op": "replace", "path": "password", "value": "Another-Strong-Pass-1234"}]
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		!has_verifier(&state, "carol"),
		"SCIM password change with scram = false must drop the verifier"
	);
}
