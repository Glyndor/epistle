//! SCIM across tenants, second part: a name taken by another tenant cannot be
//! told from a name that is not allowed, paging counts only the caller's own
//! accounts, and moving an account into a tenant at its cap is refused.

use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;

use super::tests::{CONFIGURED_TOKEN, send};
use super::tests_tenants::{account, call, tenant_key, tenants, unconfined_key, user_names};
use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope};
use crate::api::{ApiState, api_keys, router};
use crate::directory_store::AccountStore;
use crate::smtp::auth::tests::hash;

fn create_body(name: &str, email: &str) -> serde_json::Value {
	json!({
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": name,
		"active": true,
		"emails": [{"value": email}],
	})
}

#[tokio::test]
async fn a_name_taken_by_another_tenant_answers_like_a_name_that_is_not_allowed() {
	let (_dir, state, store) = tenants();
	let app = router(state);
	let taken = create_body("carol", "carol2@a.test");
	let invalid = create_body("Not A Name!", "carol2@a.test");
	let (taken_status, taken_body) =
		call(&app, "POST", "/scim/v2/Users", tenant_key(), Some(&taken)).await;
	let (invalid_status, invalid_body) =
		call(&app, "POST", "/scim/v2/Users", tenant_key(), Some(&invalid)).await;
	assert_eq!(taken_status, invalid_status);
	assert_eq!(
		taken_body, invalid_body,
		"the answer must not say the name exists elsewhere"
	);
	assert!(store.dynamic("carol2").is_none());
	// A name the caller's own tenant holds is the caller's to know about.
	let (own_status, _) = call(
		&app,
		"POST",
		"/scim/v2/Users",
		tenant_key(),
		Some(&create_body("alice", "alice2@a.test")),
	)
	.await;
	assert_eq!(own_status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn paging_counts_only_the_callers_own_accounts() {
	let (_dir, state, _store) = tenants();
	let app = router(state);
	let (status, page) = call(
		&app,
		"GET",
		"/scim/v2/Users?startIndex=2&count=1",
		tenant_key(),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(user_names(&page), ["bob"]);
	assert_eq!(page["itemsPerPage"], 1);
	let (_, past) = call(
		&app,
		"GET",
		"/scim/v2/Users?startIndex=3&count=10",
		tenant_key(),
		None,
	)
	.await;
	assert_eq!(
		user_names(&past),
		Vec::<String>::new(),
		"carol and dave are not page three"
	);
	let (_, all) = call(
		&app,
		"GET",
		"/scim/v2/Users?startIndex=3&count=10",
		unconfined_key(),
		None,
	)
	.await;
	assert_eq!(user_names(&all), ["carol", "dave"]);
}

/// Tenants `a` (cap 2, full: alice and bob) and `c` (no cap, with zed). The
/// key reaches both domains.
fn two_reachable_tenants() -> (tempfile::TempDir, ApiState, Arc<AccountStore>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let domains = vec!["a.test".to_string(), "c.test".to_string()];
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	for (name, address) in [
		("alice", "alice@a.test"),
		("bob", "bob@a.test"),
		("zed", "zed@c.test"),
	] {
		store.add(account(name, &[address])).expect("seed account");
	}
	let mut keys = ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(ApiKey {
		label: "two".to_string(),
		hash: api_keys::sha256_hash(tenant_key()),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![Scope::Scim.as_str().to_string()],
		domains: domains.clone(),
		account: None,
	})
	.expect("add key");
	drop(keys);
	let tenant = |name: &str, domain: &str, cap: Option<u64>| crate::config::Tenant {
		name: Some(name.to_string()),
		domains: vec![domain.to_string()],
		quota_bytes: None,
		max_accounts: cap,
		max_domains: None,
		submission_rate_limit_per_min: None,
	};
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		tenant("a", "a.test", Some(2)),
		tenant("c", "c.test", None),
	]));
	let state = ApiState::new(
		&hash(CONFIGURED_TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(dir.path()).expect("spool"),
	)
	.with_directory(store.handle())
	.with_tenant_limits(limits);
	(dir, state, store)
}

fn replace_body(name: &str, emails: &[&str]) -> serde_json::Value {
	json!({
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": name,
		"active": true,
		"emails": emails.iter().map(|value| json!({"value": value})).collect::<Vec<_>>(),
	})
}

#[tokio::test]
async fn an_account_cannot_be_moved_into_a_tenant_at_its_cap() {
	let (_dir, state, store) = two_reachable_tenants();
	let app = router(state);
	let body = replace_body("zed", &["zed@a.test"]);
	let (status, _) = send(
		&app,
		"PUT",
		"/scim/v2/Users/zed",
		Some(tenant_key()),
		Some(&body),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "tenant a is full");
	assert_eq!(store.dynamic("zed").expect("zed").addresses, ["zed@c.test"]);
}

#[tokio::test]
async fn adding_an_address_in_a_full_tenant_is_refused_too() {
	let (_dir, state, store) = two_reachable_tenants();
	let app = router(state);
	let body = replace_body("zed", &["zed@c.test", "zed@a.test"]);
	let (status, _) = send(
		&app,
		"PUT",
		"/scim/v2/Users/zed",
		Some(tenant_key()),
		Some(&body),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(store.dynamic("zed").expect("zed").addresses, ["zed@c.test"]);
}

#[tokio::test]
async fn changing_addresses_inside_the_accounts_own_tenant_uses_no_quota() {
	let (_dir, state, store) = two_reachable_tenants();
	let app = router(state);
	let body = replace_body("alice", &["alice@a.test", "alice2@a.test"]);
	let (status, _) = send(
		&app,
		"PUT",
		"/scim/v2/Users/alice",
		Some(tenant_key()),
		Some(&body),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"alice already counts against tenant a"
	);
	assert_eq!(store.dynamic("alice").expect("alice").addresses.len(), 2);
}
