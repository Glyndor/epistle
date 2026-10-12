//! An API key bound to one account reaches JMAP and `/api/v1/send` only; the
//! administrative routes refuse it with a 403 instead of treating it like an
//! unconfined key.

use super::tests::{request, test_state};
use super::*;
use axum::http::StatusCode;

fn store_key(dir: &std::path::Path, label: &str, secret: &str, account: Option<&str>) {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: label.to_string(),
			hash: crate::api::api_keys::sha256_hash(secret),
			expires_at: None,
			ip_cidr: None,
			scopes: ["read", "write", "send", "scim"]
				.iter()
				.map(|scope| scope.to_string())
				.collect(),
			domains: Vec::new(),
			account: account.map(str::to_string),
		})
		.expect("add key");
}

#[tokio::test]
async fn account_bound_key_is_refused_on_administrative_routes() {
	let dir = tempfile::tempdir().expect("tempdir");
	store_key(dir.path(), "alice-only", "alice-secret", Some("alice"));
	let app = router(test_state(dir.path(), 0));
	for (method, path) in [
		("GET", "/api/v1/status"),
		("GET", "/api/v1/accounts"),
		("GET", "/api/v1/domains"),
		("GET", "/api/v1/queue"),
		("GET", "/scim/v2/Users"),
	] {
		let (status, body) = request(&app, method, path, Some("alice-secret")).await;
		assert_eq!(
			status,
			StatusCode::FORBIDDEN,
			"{method} {path}: an account-bound key must not reach an administrative route"
		);
		assert_eq!(
			body["error"]["code"], "forbidden",
			"{method} {path}: the refusal comes from the account-bound gate"
		);
	}
}

#[tokio::test]
async fn account_bound_key_still_reaches_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	store_key(dir.path(), "alice-only", "alice-secret", Some("alice"));
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request(&app, "GET", "/jmap/session", Some("alice-secret")).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"JMAP is the surface an account-bound key is for"
	);
}

#[tokio::test]
async fn unbound_key_keeps_its_administrative_reach() {
	let dir = tempfile::tempdir().expect("tempdir");
	store_key(dir.path(), "admin-key", "admin-secret", None);
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("admin-secret")).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"a key without `account` is not confined"
	);
}

#[test]
fn account_bound_key_has_no_domain_scope() {
	let key = crate::api::api_keys::ApiKey {
		label: "alice-only".to_string(),
		hash: crate::api::api_keys::sha256_hash("x"),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string()],
		domains: Vec::new(),
		account: Some("alice".to_string()),
	};
	assert!(
		!crate::api::domain_scope::DomainScope::of_key(&key)
			.admits_account(["alice@example.org"].into_iter()),
		"an account-bound key must not read as server-wide in the domain scope"
	);
}

#[test]
fn account_scoped_paths_are_exactly_jmap_and_send() {
	for path in [
		"/api/v1/send",
		"/.well-known/jmap",
		"/jmap/session",
		"/jmap/api",
	] {
		assert!(account_bound::path_is_account_scoped(path), "{path}");
	}
	for path in [
		"/api/v1/sendx",
		"/api/v1/accounts",
		"/jmapx",
		"/scim/v2/Users",
	] {
		assert!(!account_bound::path_is_account_scoped(path), "{path}");
	}
}
