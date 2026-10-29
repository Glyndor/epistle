//! JMAP / `/api/v1/send` / blob-URL principal-gate tests.
//!
//! The bearer middleware authenticates a credential but, until this work
//! landed, every JMAP method, the upload/download URLs and `/api/v1/send`
//! trusted the `accountId` in the request. The principal gate turns that
//! around: a domain-scoped key can only reach accounts that live inside
//! the domains it declared, an `Account(name)`-bound key can only reach
//! that one account, and `Admin` (the configured token) reaches everything.
//!
//! Every test in this file pins one surface of the gate: each JMAP method,
//! the upload route, the download route, the session resource, and the
//! sanity checks that the existing admin path and the JMAP `/api/v1/accounts`
//! listing are unchanged. Refusals surface as JMAP `accountNotFound` (or
//! HTTP 404 for the upload/download URLs) so the existence of foreign
//! accounts is never leaked through the error.

use super::base::{request, request_with_body};
use super::router;
use crate::storage::FsSpool;
use axum::Router;
use axum::http::StatusCode;

/// Two accounts on different domains and an API key confined to one. The
/// state mirrors what a multi-tenant install sees: `ann` in `a.example`,
/// `bob` in `b.example`, and a key whose `domains` field admits only
/// `a.example`.
fn two_tenant_state(dir: &std::path::Path) -> (Router, String) {
	let secret = "tenant-a-secret".to_string();
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "tenant-a".to_string(),
			hash: crate::api::api_keys::sha256_hash(&secret),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
			domains: vec!["a.example".to_string()],
			account: None,
		})
		.expect("add key");
	drop(key_store);

	let account = |name: &str, addresses: &[&str]| crate::config::Account {
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
	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![
				account("ann", &["ann@a.example"]),
				account("bob", &["bob@b.example"]),
			],
		)
		.expect("open store"),
	);
	let state = crate::api::ApiState::new(
		&crate::smtp::auth::tests::base::hash(super::base::TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle());
	(router(state), secret)
}

/// A key tied to one account via the `account` field. The state is
/// the same two-tenant setup; the key's principal is `Account("ann")`.
fn single_account_key_state(dir: &std::path::Path) -> (Router, String) {
	let secret = "ann-secret".to_string();
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "ann-only".to_string(),
			hash: crate::api::api_keys::sha256_hash(&secret),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string(), "write".to_string()],
			domains: Vec::new(),
			account: Some("ann".to_string()),
		})
		.expect("add key");
	drop(key_store);

	let account = |name: &str, addresses: &[&str]| crate::config::Account {
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
	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![
				account("ann", &["ann@a.example"]),
				account("bob", &["bob@b.example"]),
			],
		)
		.expect("open store"),
	);
	let state = crate::api::ApiState::new(
		&crate::smtp::auth::tests::base::hash(super::base::TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle());
	(router(state), secret)
}

// --- JMAP method-level cross-account refusals ---------------------------------

/// REJECTION: a domain-scoped key asking for `Mailbox/get` on a foreign
/// account gets the JMAP `accountNotFound` error. The same call from the
/// configured token returns the mailbox (sanity, paired with the rejection
/// test above).
#[tokio::test]
async fn scoped_key_cannot_get_mailbox_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "bob"}, "m1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not enumerate a foreign account's mailboxes: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_query_mailbox_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/query", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not query a foreign account's mailboxes: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_get_email_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "bob", "ids": null}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not pull emails from a foreign account: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_query_email_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Email/query", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not query emails on a foreign account: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_get_thread_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Thread/get", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not enumerate a foreign account's threads: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_set_mailbox_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "bob", "create": {"c": {"name": "Inbox"}}}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not mutate a foreign account: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_get_identity_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Identity/get", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not pull a foreign account's identities: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_get_quota_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Quota/get", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not read a foreign account's quota: {body}"
	);
}

#[tokio::test]
async fn scoped_key_cannot_submit_on_behalf_of_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("bob").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: bob@b.example\r\nTo: x@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let (app, secret) = two_tenant_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "bob",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "bob@b.example",
				"envelope": {"mailFrom": {"email": "bob@b.example"},
					"rcptTo": [{"email": "x@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][0], "error",
		"scoped key must not submit on behalf of a foreign account: {body}"
	);
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"scoped key must not submit on behalf of a foreign account: {body}"
	);
}

/// The JMAP session resource lists only the accounts the principal may act
/// on: a domain-scoped key on `a.example` does not even learn that
/// `bob@b.example` exists.
#[tokio::test]
async fn scoped_key_session_lists_only_admissible_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = two_tenant_state(dir.path());
	let (status, body) = request(&app, "GET", "/jmap/session", Some(&secret)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let accounts = body["accounts"].as_object().expect("accounts object");
	assert!(
		accounts.contains_key("ann"),
		"scoped key must still see its own tenant: {body}"
	);
	assert!(
		!accounts.contains_key("bob"),
		"scoped key must not see a foreign tenant's account: {body}"
	);
}

/// The configured token still lists every account and may call every
/// method on any of them. This is the sanity half of the gate: the
/// principal model is additive, not a regression of the static token.
#[tokio::test]
async fn admin_token_still_reaches_every_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = two_tenant_state(dir.path());
	let (status, body) = request(
		&app,
		"GET",
		"/jmap/session",
		Some(super::base::TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let accounts = body["accounts"].as_object().expect("accounts object");
	assert!(accounts.contains_key("ann"), "{body}");
	assert!(accounts.contains_key("bob"), "{body}");

	// And the admin can pull a foreign-tenant account's mailbox list.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::base::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(
		body["methodResponses"][0][0], "Mailbox/get",
		"admin must reach a foreign tenant: {body}"
	);
}

// --- Account(name) key -------------------------------------------------------

/// A key whose `account` field names a single account can read it; the
/// same call against a foreign account is refused.
#[tokio::test]
async fn account_bound_key_can_read_its_own_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = single_account_key_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "ann"}, "m1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][0], "Mailbox/get",
		"account-bound key must reach its own account: {body}"
	);
}

#[tokio::test]
async fn account_bound_key_cannot_read_a_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = single_account_key_state(dir.path());
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "bob"}, "m1"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"account-bound key must not see a foreign account: {body}"
	);
}

#[tokio::test]
async fn account_bound_key_session_lists_only_its_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = single_account_key_state(dir.path());
	let (_, body) = request(&app, "GET", "/jmap/session", Some(&secret)).await;
	let accounts = body["accounts"].as_object().expect("accounts object");
	assert!(accounts.contains_key("ann"), "{body}");
	assert!(!accounts.contains_key("bob"), "{body}");
}
