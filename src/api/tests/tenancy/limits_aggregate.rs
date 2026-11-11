//! The per-tenant aggregate caps: the storage a tenant may fill and the
//! messages it may send inside a window.

use super::base::{TOKEN, request_with_body};
use super::limits::KEY;
use super::*;
use axum::http::StatusCode;
use std::sync::Arc;
use tower::ServiceExt;

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
			encryption_key_file: None,
			webhook: None,
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
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let domains = vec!["a.example".to_string()];
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
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account("ann", &["ann@a.example"])],
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
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
			encryption_key_file: None,
			webhook: None,
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
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let domains = vec!["a.example".to_string()];
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
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account("ann", &["ann@a.example"])],
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
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

/// Per-recipient counting on the tenant cap: a single REST send to
/// two recipients costs two units against the tenant aggregate
/// budget. With `submission_rate_limit_per_min = 2` the second
/// send is over the cap.
#[tokio::test]
async fn aggregate_rate_charges_per_recipient() {
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: None,
			max_accounts: None,
			max_domains: None,
			submission_rate_limit_per_min: Some(2),
			encryption_key_file: None,
			webhook: None,
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
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let domains = vec!["a.example".to_string()];
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
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account("ann", &["ann@a.example"])],
		)
		.expect("open store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(dir.path()).expect("open spool"),
	)
	.with_directory(store.handle())
	.with_tenant_limits(limits);
	let app = router(state);
	let first_body = serde_json::json!({
		"from": "ann@a.example",
		"to": ["r1@elsewhere.example", "r2@elsewhere.example"],
		"subject": "x",
		"text": "hi",
	});
	let (first, _) =
		request_with_body(&app, "POST", "/api/v1/send", Some(KEY), Some(first_body)).await;
	assert_eq!(first, StatusCode::OK);
	let second_body = serde_json::json!({
		"from": "ann@a.example",
		"to": ["r3@elsewhere.example"],
		"subject": "x",
		"text": "hi",
	});
	let (second, body) =
		request_with_body(&app, "POST", "/api/v1/send", Some(KEY), Some(second_body)).await;
	assert_eq!(second, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(
		body["error"]["code"], "rate_limited",
		"second send must be deferred by the tenant cap: {body}"
	);
}
