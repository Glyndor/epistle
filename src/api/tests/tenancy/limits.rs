//! The per-tenant caps the API enforces, and the accounts a tenant may
//! hold.

use super::base::{TOKEN, request_with_body};
use super::fixtures::account;
use super::*;
use axum::http::StatusCode;
use std::sync::Arc;
use tower::ServiceExt;

pub(super) const KEY: &str = "tenant-a-secret";

/// Two domains, no tenants yet — the empty `TenantLimits` must short-circuit
/// to the pre-tenancy behaviour. Building a state without `with_tenant_limits`
/// is the identity.
pub(super) fn unscoped_state(dir: &std::path::Path) -> ApiState {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			grants: Vec::new(),
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
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

/// The caps the account store enforces in its locked writes: the same
/// tenant the runtime carries, so the early check and the write agree.
fn store_caps(max_accounts: u64) -> Arc<crate::limits::Limits> {
	crate::limits::test_support::shared_from(&format!(
		"domains = [\"a.example\", \"b.example\"]\n\
		 [[tenant]]\nname = \"a\"\ndomains = [\"a.example\"]\nmax_accounts = {max_accounts}\n"
	))
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
			grants: Vec::new(),
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(KEY),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
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
		.expect("open store")
		.with_limits(store_caps(max_accounts)),
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

/// Two creations that both passed the tenant's check must not both land:
/// the count and the insert happen in the same locked write, so the second
/// one is refused.
#[tokio::test]
async fn two_creations_that_passed_the_check_leave_one_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The tenant holds one account (`ann`), so with a cap of two both
	// candidates pass the check the route makes before it writes.
	let state = capped_state(dir.path(), 2);
	let store = state.store();
	state
		.tenant_limits()
		.check_account_creation(store, &["bob@a.example".to_string()])
		.expect("bob passes the check");
	state
		.tenant_limits()
		.check_account_creation(store, &["carl@a.example".to_string()])
		.expect("carl passes the check");
	// Now the writes, in the order two requests at the same moment reach
	// them: the second one finds the first one's account in the file.
	store
		.add(account("bob", "bob@a.example"))
		.expect("bob lands");
	let refused = store.add(account("carl", "carl@a.example"));
	assert!(refused.is_err(), "the second creation must be refused");
	assert_eq!(store.dynamic_accounts().len(), 1, "only one account landed");
}

/// Two creations at the same moment leave one account: the cap is counted in
/// the write that adds one, so the loser is refused with the same `409` the
/// early check answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_creations_at_the_same_moment_leave_one_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(capped_state(dir.path(), 2));
	let start = Arc::new(tokio::sync::Barrier::new(2));
	let mut set = tokio::task::JoinSet::new();
	for name in ["bob", "carl"] {
		let (app, start) = (app.clone(), start.clone());
		set.spawn(async move {
			let request = axum::http::Request::builder()
				.method("POST")
				.uri("/api/v1/accounts")
				.header(axum::http::header::AUTHORIZATION, format!("Bearer {KEY}"))
				.header(axum::http::header::CONTENT_TYPE, "application/json")
				.body(axum::body::Body::from(
					serde_json::json!({
						"name": name,
						"addresses": [format!("{name}@a.example")],
						"password": "correct horse battery staple",
					})
					.to_string(),
				))
				.expect("request");
			start.wait().await;
			app.oneshot(request).await.expect("response").status()
		});
	}
	let mut created = 0;
	let mut refused = 0;
	while let Some(status) = set.join_next().await {
		match status.expect("create") {
			StatusCode::OK => created += 1,
			StatusCode::CONFLICT => refused += 1,
			other => panic!("unexpected {other}"),
		}
	}
	assert_eq!(created, 1, "one account was created");
	assert_eq!(refused, 1, "the other one was refused");
}
