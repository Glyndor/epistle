//! The per-tenant caps the API enforces, and the accounts a tenant may
//! hold.

use super::base::{TOKEN, request_with_body};
use super::*;
use axum::http::StatusCode;
use std::sync::Arc;

pub(super) const KEY: &str = "tenant-a-secret";

/// Two domains, no tenants yet — the empty `TenantLimits` must short-circuit
/// to the pre-tenancy behaviour. Building a state without `with_tenant_limits`
/// is the identity.
pub(super) fn unscoped_state(dir: &std::path::Path) -> ApiState {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);

	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	let account = |name: &str, addresses: &[&str]| crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
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
			vec![account("ann", &["ann@a.example"])],
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

/// Same shape as `unscoped_state` but with a `[[tenant]]` block that owns
/// `a.example` with `max_accounts = 1`. Creating a second account in
/// `a.example` must return `409 Conflict`.
pub(super) fn capped_state(dir: &std::path::Path, max_accounts: u64) -> ApiState {
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: None,
			max_accounts: Some(max_accounts),
			max_domains: None,
			submission_rate_limit_per_min: None,
			encryption_key_file: None,
			webhook: None,
		},
	]));
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);

	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	let account = |name: &str, addresses: &[&str]| crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
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
			vec![account("ann", &["ann@a.example"])],
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
	.with_tenant_limits(limits)
}

#[tokio::test]
async fn no_tenants_means_no_enforcement() {
	// Identity guarantee: a server with no `[[tenant]]` blocks behaves
	// exactly as before — no `409` on a second account, no quota check.
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(unscoped_state(dir.path()));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@a.example"],
			"password": "correct horse battery staple",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "no tenants = no cap");
}

#[tokio::test]
async fn max_accounts_admits_when_under_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(capped_state(dir.path(), 2));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@a.example"],
			"password": "correct horse battery staple",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "under cap");
}

#[tokio::test]
async fn max_accounts_rejects_with_409_when_cap_reached() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(capped_state(dir.path(), 1));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@a.example"],
			"password": "correct horse battery staple",
		})),
	)
	.await;
	// `409`, not `429`: waiting will not lift the cap, the cap lifts when
	// an account is deleted or the operator raises it.
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert_eq!(body["error"]["code"], "conflict", "{body}");
	assert!(
		body["error"]["message"]
			.as_str()
			.expect("message")
			.contains("max_accounts"),
		"{body}"
	);
}

#[tokio::test]
async fn max_accounts_does_not_apply_outside_the_tenant() {
	// `b.example` is not in any tenant. A `[[tenant]]` capping `a.example`
	// must not block account creation in `b.example`.
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(capped_state(dir.path(), 1));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@b.example"],
			"password": "correct horse battery staple",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "outside the tenant");
}
