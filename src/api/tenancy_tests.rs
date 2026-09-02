//! End-to-end checks that a domain-confined API key sees and touches only its
//! own tenant. The scope logic itself is unit-tested in `domain_scope_tests`;
//! these pin the wiring, which is the half a refactor silently drops.

use super::tests::{TOKEN, request, request_with_body};
use super::*;
use axum::http::StatusCode;

const KEY: &str = "tenant-a-secret";

/// Two domains, an account on each, plus one account straddling both, and a
/// `read`+`write` key confined to `a.example`.
fn scoped_state(dir: &std::path::Path) -> ApiState {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string()],
			domains: vec!["a.example".to_string()],
		})
		.expect("add key");
	drop(key_store);

	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	let account = |name: &str, addresses: &[&str]| crate::config::Account {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![
				account("ann", &["ann@a.example"]),
				account("both", &["both@a.example", "both@b.example"]),
			],
		)
		.expect("open store"),
	);
	// `bob` is added dynamically, not from config: a config account refuses to
	// be deleted or repassworded on its own, which would make every rejection
	// below pass with the scope check removed.
	store
		.add(crate::directory_store::DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@b.example".to_string()],
			password_hash: "$argon2id$secret".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			allowed_protocols: None,
		})
		.expect("add bob");
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
async fn a_scoped_key_lists_only_its_own_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, body) = request(&app, "GET", "/api/v1/accounts", Some(KEY)).await;
	assert_eq!(status, StatusCode::OK);
	let names: Vec<&str> = body["accounts"]
		.as_array()
		.expect("array")
		.iter()
		.map(|a| a["name"].as_str().expect("name"))
		.collect();
	// `both` is absent as well: an account holding an address in each domain
	// belongs to both tenants, so neither may act on it alone.
	assert_eq!(names, vec!["ann"], "{body}");
}

#[tokio::test]
async fn the_configured_token_still_sees_everything() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		body["accounts"].as_array().expect("array").len(),
		3,
		"{body}"
	);
}

#[tokio::test]
async fn a_scoped_key_lists_only_its_own_domains() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, body) = request(&app, "GET", "/api/v1/domains", Some(KEY)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["domains"], serde_json::json!(["a.example"]), "{body}");
}

#[tokio::test]
async fn a_scoped_key_cannot_delete_another_tenants_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, _) = request(&app, "DELETE", "/api/v1/accounts/bob", Some(KEY)).await;
	// 404, not 403: the status code must not confirm that `bob` exists.
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_scoped_key_cannot_reset_another_tenants_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, _) = request_with_body(
		&app,
		"PUT",
		"/api/v1/accounts/bob/password",
		Some(KEY),
		Some(serde_json::json!({ "password": "correct horse battery staple" })),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_scoped_key_cannot_list_another_tenants_mailboxes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, _) = request(&app, "GET", "/api/v1/accounts/bob/mailboxes", Some(KEY)).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_scoped_key_cannot_mint_an_address_outside_its_domains() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(KEY),
		Some(serde_json::json!({
			"name": "sneak",
			"addresses": ["sneak@b.example"],
			"password": "correct horse battery staple",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_scoped_key_can_still_work_inside_its_own_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scoped_state(dir.path()));
	let (status, _) = request(&app, "GET", "/api/v1/accounts/ann/mailboxes", Some(KEY)).await;
	// The confinement must not turn into a key that can do nothing at all.
	assert_eq!(status, StatusCode::OK);
}
