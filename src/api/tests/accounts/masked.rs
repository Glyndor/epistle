//! The masked addresses an account creates and keeps.

use super::base::{TOKEN, request, request_with_body, test_state};
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

/// Two domains configured, with the account living on the second one.
fn two_domain_state(dir: &std::path::Path) -> ApiState {
	let domains = vec!["first.example".to_string(), "second.example".to_string()];
	let accounts = vec![crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: "bob".to_string(),
		addresses: vec!["bob@second.example".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
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
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
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

#[tokio::test]
async fn create_refuses_a_mask_on_a_disabled_domain_without_storing_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state =
		two_domain_state(dir.path()).with_disabled_domains(vec!["SECOND.EXAMPLE".to_string()]);
	let app = router(state);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/bob/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "shopping" })),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(body["error"]["code"], "conflict");
	assert!(
		body["error"]["message"]
			.as_str()
			.unwrap()
			.contains("second.example")
	);
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/bob/masked",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"].as_array().expect("array").len(), 0);
}

#[tokio::test]
async fn create_still_mints_a_mask_when_only_another_domain_is_disabled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state =
		two_domain_state(dir.path()).with_disabled_domains(vec!["first.example".to_string()]);
	let app = router(state);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/bob/masked",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({ "label": "shopping" })),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let address = body["address"].as_str().expect("address");
	assert!(
		address.ends_with("@second.example"),
		"unexpected address: {address}"
	);
}
