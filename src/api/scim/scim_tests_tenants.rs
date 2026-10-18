//! SCIM with an API key confined to one tenant's domains: it provisions that
//! tenant's accounts and nobody else's. Two tenants, `a.test` and `b.test`,
//! each with two accounts; the tenant key carries `domains = ["a.test"]`.

use axum::Router;
use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;

use super::tests::{CONFIGURED_TOKEN, app, send};
use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope};
use crate::api::{ApiState, api_keys};
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::hash;
use crate::test_fixtures as fixtures;

/// Reach of the key issued to tenant A (`--domain a.test`).
pub(super) fn tenant_key() -> &'static str {
	fixtures::api_key()
}

/// A SCIM key with no domains: sees every tenant.
pub(super) fn unconfined_key() -> &'static str {
	fixtures::second_password()
}

pub(super) fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
		password_hash: hash(fixtures::password()),
		..DynamicAccount::default()
	}
}

/// `a.test` is capped at three accounts, `b.test` is not.
pub(super) fn tenants() -> (tempfile::TempDir, ApiState, Arc<AccountStore>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let domains = vec!["a.test".to_string(), "b.test".to_string()];
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
		("carol", "carol@b.test"),
		("dave", "dave@b.test"),
	] {
		store.add(account(name, &[address])).expect("seed account");
	}
	let mut keys = ApiKeyStore::open(dir.path()).expect("key store");
	for (label, secret, domains) in [
		("tenant-a", tenant_key(), vec!["a.test".to_string()]),
		("scim-all", unconfined_key(), Vec::new()),
	] {
		keys.add(ApiKey {
			label: label.to_string(),
			hash: api_keys::sha256_hash(secret),
			expires_at: None,
			ip_cidr: None,
			scopes: vec![Scope::Scim.as_str().to_string()],
			domains,
			account: None,
		})
		.expect("add key");
	}
	drop(keys);
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.test".to_string()],
			quota_bytes: None,
			max_accounts: Some(3),
			max_domains: None,
			submission_rate_limit_per_min: None,
		},
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

pub(super) async fn call(
	app: &Router,
	method: &str,
	path: &str,
	key: &str,
	body: Option<&serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	send(app, method, path, Some(key), body).await
}

pub(super) fn user_names(list: &serde_json::Value) -> Vec<String> {
	let mut names: Vec<String> = list["Resources"]
		.as_array()
		.expect("resources")
		.iter()
		.map(|user| user["userName"].as_str().expect("userName").to_string())
		.collect();
	names.sort();
	names
}

#[tokio::test]
async fn the_list_holds_only_the_tenants_own_accounts() {
	let (_dir, state, _store) = tenants();
	let app = app(state);
	let (status, own) = call(&app, "GET", "/scim/v2/Users", tenant_key(), None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(user_names(&own), ["alice", "bob"]);
	assert_eq!(own["totalResults"], 2);
	let (_, all) = call(&app, "GET", "/scim/v2/Users", unconfined_key(), None).await;
	assert_eq!(user_names(&all), ["alice", "bob", "carol", "dave"]);
}

#[tokio::test]
async fn a_filter_cannot_reach_another_tenants_account() {
	let (_dir, state, _store) = tenants();
	let app = app(state);
	let path = "/scim/v2/Users?filter=userName%20eq%20%22carol%22";
	let (status, found) = call(&app, "GET", path, tenant_key(), None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(found["totalResults"], 0, "carol belongs to b.test");
}

#[tokio::test]
async fn another_tenants_account_is_not_found_by_id() {
	let (_dir, state, _store) = tenants();
	let app = app(state);
	let (status, _) = call(&app, "GET", "/scim/v2/Users/carol", tenant_key(), None).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, body) = call(&app, "GET", "/scim/v2/Users/alice", tenant_key(), None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["userName"], "alice");
	let (status, _) = call(&app, "GET", "/scim/v2/Users/carol", unconfined_key(), None).await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_password_of_another_tenants_account_cannot_be_set() {
	let (_dir, state, store) = tenants();
	let app = app(state);
	let before = store.dynamic("carol").expect("carol").password_hash;
	let patch = json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "path": "password", "value": fixtures::second_password()}],
	});
	let (status, _) = call(
		&app,
		"PATCH",
		"/scim/v2/Users/carol",
		tenant_key(),
		Some(&patch),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let put = json!({
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "carol",
		"active": true,
		"password": fixtures::second_password(),
		"emails": [{"value": "carol@b.test"}],
	});
	let (status, _) = call(
		&app,
		"PUT",
		"/scim/v2/Users/carol",
		tenant_key(),
		Some(&put),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(store.dynamic("carol").expect("carol").password_hash, before);
}

#[tokio::test]
async fn another_tenants_account_cannot_be_deactivated_or_removed() {
	let (_dir, state, store) = tenants();
	let app = app(state);
	let deactivate = json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "path": "active", "value": false}],
	});
	let (status, _) = call(
		&app,
		"PATCH",
		"/scim/v2/Users/dave",
		tenant_key(),
		Some(&deactivate),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(!store.dynamic("dave").expect("dave").disabled);
	let (status, _) = call(&app, "DELETE", "/scim/v2/Users/dave", tenant_key(), None).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(store.dynamic("dave").is_some(), "dave must still exist");
}

#[tokio::test]
async fn an_account_with_an_address_in_each_tenant_is_out_of_reach() {
	let (_dir, state, store) = tenants();
	store
		.add(account("eve", &["eve@a.test", "eve@b.test"]))
		.expect("straddling account");
	let app = app(state);
	let (status, _) = call(&app, "GET", "/scim/v2/Users/eve", tenant_key(), None).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = call(&app, "DELETE", "/scim/v2/Users/eve", tenant_key(), None).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(store.dynamic("eve").is_some());
}

#[tokio::test]
async fn an_account_cannot_be_created_with_an_address_in_another_tenant() {
	let (_dir, state, store) = tenants();
	let app = app(state);
	for emails in [
		json!([{"value": "ceo@b.test"}]),
		json!([{"value": "mallory@a.test"}, {"value": "mallory@b.test"}]),
		json!([]),
	] {
		let body = json!({
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "mallory",
			"active": true,
			"emails": emails,
		});
		let (status, _) = call(&app, "POST", "/scim/v2/Users", tenant_key(), Some(&body)).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "emails {emails}");
		assert!(store.dynamic("mallory").is_none());
	}
}

#[tokio::test]
async fn a_replace_cannot_move_an_account_to_another_tenant() {
	let (_dir, state, store) = tenants();
	let app = app(state);
	let put = json!({
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@a.test"}, {"value": "alice@b.test"}],
	});
	let (status, _) = call(
		&app,
		"PUT",
		"/scim/v2/Users/alice",
		tenant_key(),
		Some(&put),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		store.dynamic("alice").expect("alice").addresses,
		["alice@a.test"]
	);
}

#[tokio::test]
async fn creating_users_stops_at_the_tenants_account_cap() {
	let (_dir, state, store) = tenants();
	let app = app(state);
	let create = |name: &str| {
		json!({
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": name,
			"active": true,
			"emails": [{"value": format!("{name}@a.test")}],
		})
	};
	let (status, _) = call(
		&app,
		"POST",
		"/scim/v2/Users",
		tenant_key(),
		Some(&create("fred")),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::CREATED,
		"the third account fits the cap of 3"
	);
	let (status, _) = call(
		&app,
		"POST",
		"/scim/v2/Users",
		tenant_key(),
		Some(&create("gina")),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::CONFLICT,
		"the fourth account is over the cap"
	);
	assert!(store.dynamic("gina").is_none());
}

#[tokio::test]
async fn an_unconfined_key_still_provisions_every_tenant() {
	let (_dir, state, store) = tenants();
	let app = app(state);
	let deactivate = json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "path": "active", "value": false}],
	});
	let (status, _) = call(
		&app,
		"PATCH",
		"/scim/v2/Users/dave",
		unconfined_key(),
		Some(&deactivate),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(store.dynamic("dave").expect("dave").disabled);
	let (status, _) = call(
		&app,
		"DELETE",
		"/scim/v2/Users/carol",
		unconfined_key(),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NO_CONTENT);
}
