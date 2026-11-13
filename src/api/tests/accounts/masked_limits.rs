//! The limits and the scope checks the masked-address surface applies.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

#[tokio::test]
async fn limit_returns_409_not_429() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![crate::config::Account {
				send: None,
				receive: None,
				display_name: None,
				name: "alice".to_string(),
				addresses: vec!["alice@example.org".to_string()],
				password_hash: Some("$argon2id$secret".to_string()),
				catch_all: Vec::new(),
				quota_bytes: None,
				forward: Vec::new(),
				forward_keep_local: true,
				allowed_protocols: None,
			}],
		)
		.expect("store")
		.with_masked_max(1),
	);
	let mut state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
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
			account: None,
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
	assert_eq!(status, StatusCode::FORBIDDEN);

	// PATCH is rejected: read scope cannot toggle masks.
	let (status, _) = request_with_body(
		&app,
		"PATCH",
		"/api/v1/accounts/alice/masked/none@example.org",
		Some("reader-secret"),
		Some(serde_json::json!({ "enabled": false })),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);

	// DELETE is rejected: read scope cannot revoke masks.
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/alice/masked/none@example.org",
		Some("reader-secret"),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
}
