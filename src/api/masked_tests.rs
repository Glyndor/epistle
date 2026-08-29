//! Tests for the `/api/v1/accounts/{name}/masked` surface: lifecycle, scope
//! enforcement, limit, and the disabled-mask rejection contract.

use super::tests::{TOKEN, request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

#[tokio::test]
async fn list_starts_empty_for_a_fresh_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"].as_array().expect("array").len(), 0);
}

#[tokio::test]
async fn create_returns_201_with_a_generated_address_and_lists_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "shopping" })),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let address = body["address"].as_str().expect("address").to_string();
	assert!(
		address.starts_with("shopping.") && address.ends_with("@example.org"),
		"unexpected address: {address}"
	);

	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let addresses = body["addresses"].as_array().expect("array");
	assert_eq!(addresses.len(), 1);
	assert_eq!(addresses[0]["address"], address);
	assert_eq!(addresses[0]["label"], "shopping");
	assert_eq!(addresses[0]["enabled"], true);
	assert!(addresses[0]["last_used_at"].is_null(), "{addresses:?}");
}

#[tokio::test]
async fn patch_disables_and_reenables_a_mask() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "newsletter" })),
	)
	.await;
	let address = body["address"].as_str().expect("address").to_string();

	let (status, body) = request_with_body(
		&app,
		"PATCH",
		&format!("/api/v1/accounts/alice/masked/{address}"),
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "enabled": false })),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["enabled"], false);

	let (_, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(body["addresses"][0]["enabled"], false);

	let (status, _) = request_with_body(
		&app,
		"PATCH",
		&format!("/api/v1/accounts/alice/masked/{address}"),
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "enabled": true })),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn delete_removes_a_mask() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "throwaway" })),
	)
	.await;
	let address = body["address"].as_str().expect("address").to_string();

	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/accounts/alice/masked/{address}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["removed"], address);

	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/accounts/alice/masked/{address}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn patch_unknown_address_is_404() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"PATCH",
		"/api/v1/accounts/alice/masked/does-not-exist@example.org",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "enabled": false })),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn limit_returns_409_not_429() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![crate::config::Account {
				name: "alice".to_string(),
				addresses: vec!["alice@example.org".to_string()],
				password_hash: Some("$argon2id$secret".to_string()),
				catch_all: Vec::new(),
				quota_bytes: None,
				forward: Vec::new(),
				forward_keep_local: true,
			}],
		)
		.expect("store")
		.with_masked_max(1),
	);
	let mut state = ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		crate::storage::FsSpool::open(dir.path()).expect("spool"),
	)
	.with_directory(store.handle());
	if let Some(authz) = None {
		state = state.with_authz(authz);
	}
	let app = router(state);

	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "first" })),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "second" })),
	)
	.await;
	// 409, not 429: the cap does not lift with time, so telling the client to
	// retry would send it into a loop that can never succeed.
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn disabled_mask_is_not_sendable_by_its_owner() {
	// End-to-end: the API creates and disables a mask, then the directory
	// reports `owns_address == false` for the owner — disabled masks are
	// absent from the directory map, so `owns_address` fails closed.
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "newsletter" })),
	)
	.await;
	let address = body["address"].as_str().expect("address").to_string();

	// While enabled, the owner can send from the mask.
	let state = test_state(dir.path(), 0);
	let parsed = crate::smtp::address::Address::parse(&address).expect("parse");
	assert!(
		state.owns_address("alice", &parsed),
		"enabled mask must be sendable by its owner"
	);

	// Disable the mask through the API.
	let (status, _) = request_with_body(
		&app,
		"PATCH",
		&format!("/api/v1/accounts/alice/masked/{address}"),
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "enabled": false })),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	// And the directory now refuses the same address from the owner: a
	// disabled mask is not in `masked_by_address`, so the SMTP and JMAP
	// send-as paths both fail closed without leaking that the mask existed.
	let state = test_state(dir.path(), 0);
	assert!(
		!state.owns_address("alice", &parsed),
		"disabled mask must not be sendable by its owner"
	);
}

/// The 403 control: a `read`-only key cannot create, update or delete masked
/// addresses, but can still list them. A leaked `read` key therefore learns
/// which addresses an account owns but cannot mutate the list.
#[tokio::test]
async fn read_scope_is_rejected_on_masked_mutators() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open");
	key_store
		.add(crate::api::ApiKey {
			label: "reader".to_string(),
			hash: crate::api::api_keys::sha256_hash("reader-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
		})
		.expect("add");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));

	// GET works: read scope admits the listing.
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/masked",
		Some("reader-secret"),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	// POST is rejected: read scope cannot mint masks.
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some("reader-secret"),
		Some(serde_json::json!({ "label": "x" })),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);

	// PATCH is rejected: read scope cannot toggle masks.
	let (status, _) = request_with_body(
		&app,
		"PATCH",
		"/api/v1/accounts/alice/masked/none@example.org",
		Some("reader-secret"),
		Some(serde_json::json!({ "enabled": false })),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);

	// DELETE is rejected: read scope cannot revoke masks.
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/alice/masked/none@example.org",
		Some("reader-secret"),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Two domains configured, with the account living on the second one.
fn two_domain_state(dir: &std::path::Path) -> ApiState {
	let domains = vec!["first.example".to_string(), "second.example".to_string()];
	let accounts = vec![crate::config::Account {
		name: "bob".to_string(),
		addresses: vec!["bob@second.example".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle())
}

#[tokio::test]
async fn a_mask_lands_on_the_account_own_domain_not_the_first_configured() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(two_domain_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/bob/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "shopping" })),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let address = body["address"].as_str().expect("address");
	// `domains` is a list and accounts are keyed by full address. Handing bob
	// a mask at first.example would put it on a domain he has nothing to do
	// with, and every mask in the install would break the day that domain is
	// dropped from the config.
	assert!(
		address.ends_with("@second.example"),
		"mask landed off the account's own domain: {address}"
	);
}
