//! End-to-end checks that the per-tenant aggregate limits are enforced
//! through the API. The runtime primitives (counter math, keying) live in
//! `tenant_limits_tests`; these pin the HTTP wiring, which is the half a
//! refactor silently drops.

use super::tests::{TOKEN, request_with_body};
use super::*;
use axum::http::StatusCode;
use std::sync::Arc;
use tower::ServiceExt;

const KEY: &str = "tenant-a-secret";

/// Two domains, no tenants yet — the empty `TenantLimits` must short-circuit
/// to the pre-tenancy behaviour. Building a state without `with_tenant_limits`
/// is the identity.
fn unscoped_state(dir: &std::path::Path) -> ApiState {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
			domains: Vec::new(),
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
			vec![account("ann", &["ann@a.example"])],
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

/// Same shape as `unscoped_state` but with a `[[tenant]]` block that owns
/// `a.example` with `max_accounts = 1`. Creating a second account in
/// `a.example` must return `409 Conflict`.
fn capped_state(dir: &std::path::Path, max_accounts: u64) -> ApiState {
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: None,
			max_accounts: Some(max_accounts),
			max_domains: None,
			submission_rate_limit_per_min: None,
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
			vec![account("ann", &["ann@a.example"])],
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

#[tokio::test]
async fn aggregate_quota_blocks_an_over_cap_upload() {
	// Tiny tenant quota (1 byte) for `a.example`. The default per-account
	// quota is 0 (unlimited), so the aggregate check is the only thing
	// that can reject.
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: Some(1),
			max_accounts: None,
			max_domains: None,
			submission_rate_limit_per_min: None,
		},
	]));
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string()],
			domains: Vec::new(),
		})
		.expect("add key");
	drop(key_store);
	let domains = vec!["a.example".to_string()];
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
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account("ann", &["ann@a.example"])],
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(dir.path()).expect("open spool"),
	)
	.with_directory(store.handle())
	.with_tenant_limits(limits);
	let app = router(state);

	// Upload at least one byte: the aggregate cap of 1 byte is already at
	// the limit because `account_usage_bytes` is inclusive of sidecars.
	let body = axum::body::Body::from(vec![b'x'; 4]);
	let request = axum::http::Request::builder()
		.method("POST")
		.uri("/jmap/upload/ann")
		.header(axum::http::header::AUTHORIZATION, format!("Bearer {KEY}"))
		.header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
		.body(body)
		.expect("request");
	let response = app.oneshot(request).await.expect("response");
	assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn aggregate_rate_blocks_a_second_send_within_the_window() {
	// One submission per minute across the tenant. First send succeeds,
	// second one in the same window returns 429.
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: None,
			max_accounts: None,
			max_domains: None,
			submission_rate_limit_per_min: Some(1),
		},
	]));
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "send".to_string()],
			domains: Vec::new(),
		})
		.expect("add key");
	drop(key_store);
	let domains = vec!["a.example".to_string()];
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
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account("ann", &["ann@a.example"])],
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(dir.path()).expect("open spool"),
	)
	.with_directory(store.handle())
	.with_tenant_limits(limits);
	let app = router(state);

	let send = || {
		serde_json::json!({
			"from": "ann@a.example",
			"to": ["someone@elsewhere.example"],
			"subject": "x",
			"text": "hi",
		})
	};
	let (first, _) = request_with_body(&app, "POST", "/api/v1/send", Some(KEY), Some(send())).await;
	assert_eq!(first, StatusCode::OK);
	let (second, body) =
		request_with_body(&app, "POST", "/api/v1/send", Some(KEY), Some(send())).await;
	assert_eq!(second, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"]["code"], "rate_limited", "{body}");
	assert!(
		body["error"]["message"]
			.as_str()
			.expect("message")
			.contains("rate limit"),
		"{body}"
	);
}
