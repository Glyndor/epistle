//! Tests for `/api/v1/auth/verify` — panel credential verification.

use std::sync::Arc;

use crate::directory_store::{AccountStore, SqlAccount};
use crate::smtp::auth::tests::base::hash as hash_password;
use crate::storage::FsSpool;
use crate::test_fixtures as fixtures;
use axum::http::StatusCode;
use serde_json::json;

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::state::ApiState;

fn test_password() -> &'static str {
	fixtures::password()
}

async fn create_account(app: &axum::Router, name: &str, password: &str) {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(json!({
			"name": name,
			"addresses": [format!("{name}@example.org")],
			"password": password,
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn verify_flags_a_valid_admin() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_admins(vec!["ops".to_string()]));
	create_account(&app, "ops", test_password()).await;

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({"name": "ops@example.org", "password": test_password()})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["valid"], true);
	assert_eq!(body["admin"], true);
}

#[tokio::test]
async fn verify_accepts_a_valid_non_admin_without_admin() {
	let dir = tempfile::tempdir().expect("tempdir");
	// No admins configured: a valid account is a user, never an admin.
	let app = router(test_state(dir.path(), 0));
	create_account(&app, "user", test_password()).await;

	let (_, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({"name": "user@example.org", "password": test_password()})),
	)
	.await;
	assert_eq!(body["valid"], true);
	assert_eq!(body["admin"], false);
}

#[tokio::test]
async fn verify_rejects_wrong_password_and_unknown_account_identically() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_admins(vec!["ops".to_string()]));
	create_account(&app, "ops", test_password()).await;

	// Wrong password for a real (admin) account.
	let (_, wrong) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({"name": "ops@example.org", "password": fixtures::wrong_password()})),
	)
	.await;
	assert_eq!(wrong["valid"], false);
	assert_eq!(
		wrong["admin"], false,
		"admin must never leak on a bad password"
	);

	// Unknown account — indistinguishable from the wrong-password case.
	let (_, unknown) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({"name": "ghost@example.org", "password": test_password()})),
	)
	.await;
	assert_eq!(unknown, wrong);
}

#[tokio::test]
async fn verify_requires_the_bearer_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		None,
		Some(json!({"name": "x@example.org", "password": test_password()})),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// --- SQL directory regression -------------------------------------------------
//
// Before this fix, `account_in_scope` always required the resolved account to
// appear in the static+dynamic listing that `state.accounts()` returns, even
// when the bearer had no `domains` of its own. A SQL-sourced account whose
// password authenticates through the directory was then answered with
// `valid: false` because its name never reaches that listing. The fix lets
// the configured token and administrative keys without `account` or `domains` skip the membership check
// entirely (the pre-tenancy `0.12.1` behaviour); a key confined to some
// domains still relies on the static+dynamic listing, so an account the
// listing cannot resolve against stays "fail closed", as documented in
// `docs/api.md` as the known limit on confined keys.

/// Build an `ApiState` whose directory carries one SQL account but no static
/// or dynamic row for it. If `key` is `Some`, the matching API key is written
/// into `api_keys.toml` first so `ApiState::new` loads it from disk.
fn sql_account_state(dir: &std::path::Path, key: Option<super::api_keys::ApiKey>) -> ApiState {
	sql_account_state_counted(dir, key).0
}

fn count_directory(
	handle: &crate::directory_store::DirectoryHandle,
) -> Arc<crate::smtp::directory::tests::decoy_counters::DecoyCounters> {
	let counters =
		Arc::new(crate::smtp::directory::tests::decoy_counters::DecoyCounters::default());
	let directory = handle.current();
	handle.replace(crate::smtp::directory::Directory::default());
	let directory = Arc::try_unwrap(directory).expect("exclusive directory snapshot");
	handle.replace(directory.with_decoy_counters(counters.clone()));
	counters
}

fn sql_account_state_counted(
	dir: &std::path::Path,
	key: Option<super::api_keys::ApiKey>,
) -> (
	ApiState,
	Arc<crate::smtp::directory::tests::decoy_counters::DecoyCounters>,
) {
	if let Some(key) = key {
		let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
		key_store.add(key).expect("add key");
	}
	let domains = vec!["sql.example".to_string(), "other.example".to_string()];
	let spool = FsSpool::open(dir).expect("open spool");
	let store = Arc::new(
		AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store"),
	);
	let hash = hash_password(test_password());
	store.set_sql_accounts(vec![SqlAccount {
		name: "sql-user".to_string(),
		addresses: vec!["sql-user@sql.example".to_string()],
		password_hash: Some(hash),
	}]);
	let counters = count_directory(&store.handle());
	let state = ApiState::new(
		&hash_password(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		spool,
	)
	.with_directory(store.handle());
	(state, counters)
}

/// Write-scoped key (the scope the bearer middleware assigns to
/// `POST /api/v1/auth/verify`) the post-auth scope check must answer
/// correctly for a SQL-sourced login. An empty `domains` list leaves the key
/// unrestricted; passing a domain narrows the reach.
fn verify_key(secret: &str, domains: Vec<String>) -> super::api_keys::ApiKey {
	super::api_keys::ApiKey {
		label: "ci".to_string(),
		hash: super::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["write".to_string()],
		domains,
		account: None,
	}
}

/// The configured token is an unconfined bearer, so the post-auth scope check
/// must not consult the static+dynamic listing at all. The SQL row
/// authenticates and the response is `valid: true`.
#[tokio::test]
async fn verify_accepts_sql_account_with_the_configured_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(sql_account_state(dir.path(), None));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({
			"name": "sql-user@sql.example",
			"password": test_password(),
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["valid"], true);
	assert_eq!(body["admin"], false);
}

/// A write-scoped administrative key without `domains` is also unrestricted,
/// so it must reach the SQL-backed account too.
#[tokio::test]
async fn verify_accepts_sql_account_with_a_key_without_domains() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = "no-domains-secret";
	let app = router(sql_account_state(
		dir.path(),
		Some(verify_key(secret, Vec::new())),
	));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(secret),
		Some(json!({
			"name": "sql-user@sql.example",
			"password": test_password(),
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["valid"], true);
}

/// A key confined to the account's own domain still relies on the
/// static+dynamic listing (a SQL row is not projected into it), so the
/// post-auth check fails closed. The response stays `valid: false` and
/// `admin: false`, matching the ordinary rejection shape and the limit
/// documented in `docs/api.md`.
#[tokio::test]
async fn verify_rejects_sql_account_with_a_key_confined_to_its_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = "own-tenant-secret";
	let app = router(sql_account_state(
		dir.path(),
		Some(verify_key(secret, vec!["sql.example".to_string()])),
	));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(secret),
		Some(json!({
			"name": "sql-user@sql.example",
			"password": test_password(),
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["valid"], false,
		"a confined key must not confirm a SQL account the static+dynamic listing cannot resolve"
	);
}

/// A wrong password against a real SQL account answers identically to a
/// nonexistent login, matching the no-user-enumeration oracle the mail
/// protocols already give and the behaviour for static accounts.
#[tokio::test]
async fn verify_rejects_wrong_password_and_unknown_sql_account_identically() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(sql_account_state(dir.path(), None));

	let (_, wrong) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({
			"name": "sql-user@sql.example",
			"password": fixtures::wrong_password(),
		})),
	)
	.await;
	assert_eq!(wrong["valid"], false);
	assert_eq!(wrong["admin"], false);

	let (_, unknown) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({
			"name": "ghost@sql.example",
			"password": test_password(),
		})),
	)
	.await;
	assert_eq!(unknown, wrong);
}

#[tokio::test]
async fn confined_verify_never_checks_out_of_scope_passwords() {
	for domain in ["sql.example", "other.example"] {
		let dir = tempfile::tempdir().unwrap();
		let secret = "confined-password-counter";
		let (state, counters) =
			sql_account_state_counted(dir.path(), Some(verify_key(secret, vec![domain.into()])));
		let app = router(state);
		for login in ["sql-user", "sql-user@sql.example", "ghost@sql.example"] {
			for password in [test_password(), fixtures::wrong_password()] {
				let response = request_with_body(
					&app,
					"POST",
					"/api/v1/auth/verify",
					Some(secret),
					Some(json!({"name": login, "password": password})),
				)
				.await;
				assert_eq!(
					response,
					(StatusCode::OK, json!({"valid": false, "admin": false}))
				);
				assert_eq!(counters.hashes(), 0, "{domain}: {login}");
				assert_eq!(counters.password(), 0, "{domain}: {login}");
			}
		}
	}
}

#[tokio::test]
async fn confined_verify_checks_the_effective_owner_after_authentication() {
	let dir = tempfile::tempdir().unwrap();
	let secret = "effective-owner-secret";
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).unwrap();
	keys.add(verify_key(secret, vec!["sql.example".into()]))
		.unwrap();
	// The first claimant owns the address, but a later row admits the login.
	let accounts = [
		("owner", vec!["shared@sql.example", "owner@other.example"]),
		("shadow", vec!["shared@sql.example"]),
	]
	.into_iter()
	.map(|(name, addresses)| crate::config::Account {
		name: name.into(),
		addresses: addresses.into_iter().map(String::from).collect(),
		password_hash: Some(hash_password(test_password())),
		display_name: None,
		catch_all: vec![],
		quota_bytes: None,
		forward: vec![],
		forward_keep_local: true,
		allowed_protocols: None,
	})
	.collect();
	let domains = vec!["sql.example".into(), "other.example".into()];
	let store = Arc::new(
		AccountStore::open(dir.path(), domains.clone(), Default::default(), accounts).unwrap(),
	);
	let counters = count_directory(&store.handle());
	let state = ApiState::new(
		&hash_password(TOKEN.as_str()),
		dir.path().into(),
		domains,
		store.clone(),
		FsSpool::open(dir.path()).unwrap(),
	)
	.with_directory(store.handle())
	.with_admins(vec!["owner".into()]);
	let app = router(state);
	let response = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(secret),
		Some(json!({"name": "shared@sql.example", "password": test_password()})),
	)
	.await;
	assert_eq!(
		response,
		(StatusCode::OK, json!({"valid": false, "admin": false}))
	);
	assert_eq!(
		counters.hashes(),
		1,
		"precheck must admit the login and authenticate its owner"
	);
}
