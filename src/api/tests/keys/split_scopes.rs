//! Management and mail are separate scopes: a key made to manage accounts does
//! not open JMAP, a key made to read mail does not open the management views,
//! and a key from 0.14.0 keeps both.

use super::base::{request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

/// A router whose key store holds one key, `secret`, with the scope names
/// given (in either vocabulary: the store keeps both fields).
fn app_with(dir: &std::path::Path, secret: &str, names: &[&str]) -> axum::Router {
	app_bound(dir, secret, names, None)
}

/// [`app_with`] for a key bound to `account`.
fn app_bound(
	dir: &std::path::Path,
	secret: &str,
	names: &[&str],
	account: Option<&str>,
) -> axum::Router {
	let mut store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	store
		.add(crate::api::api_keys::ApiKey {
			label: "k".to_string(),
			hash: crate::api::api_keys::sha256_hash(secret),
			expires_at: None,
			ip_cidr: None,
			scopes: names.iter().map(|name| (*name).to_string()).collect(),
			grants: Vec::new(),
			domains: Vec::new(),
			account: account.map(str::to_string),
			auto_submitted: false,
		})
		.expect("add key");
	drop(store);
	router(test_state(dir, 0))
}

/// One JMAP method call; the status and the first method response.
async fn jmap(app: &axum::Router, secret: &str, method: &str) -> (StatusCode, Value) {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(secret),
		Some(json!({ "methodCalls": [[method, { "accountId": "nobody" }, "c1"]] })),
	)
	.await;
	let response = body["methodResponses"][0].clone();
	(status, response)
}

/// The status of a request whose answer is not JSON.
async fn status_only(app: &axum::Router, method: &str, path: &str, secret: &str) -> StatusCode {
	use tower::ServiceExt;
	let request = axum::http::Request::builder()
		.method(method)
		.uri(path)
		.header(
			axum::http::header::AUTHORIZATION,
			format!("Bearer {secret}"),
		)
		.header(axum::http::header::CONTENT_TYPE, "application/json")
		.body(axum::body::Body::from("{}"))
		.expect("request");
	app.clone()
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

fn is_forbidden(response: &Value) -> bool {
	response[0] == "error" && response[1]["type"] == "forbidden"
}

#[tokio::test]
async fn legacy_read_reaches_management_and_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "reader", &["read"]);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("reader")).await;
	assert_eq!(status, StatusCode::OK, "management read");
	let (status, response) = jmap(&app, "reader", "Email/get").await;
	assert_eq!(status, StatusCode::OK);
	assert!(!is_forbidden(&response), "mail read: {response}");
}

#[tokio::test]
async fn legacy_write_reaches_management_and_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "writer", &["write"]);
	let status = status_only(&app, "POST", "/api/v1/domains", "writer").await;
	assert_ne!(status, StatusCode::FORBIDDEN, "management write");
	let (status, response) = jmap(&app, "writer", "Email/set").await;
	assert_eq!(status, StatusCode::OK);
	assert!(!is_forbidden(&response), "mail write: {response}");
}

#[tokio::test]
async fn manage_write_cannot_set_email() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "manager", &["manage:read", "manage:write"]);
	// The coarse check turns a key with no mail scope away from JMAP.
	let (status, _) = jmap(&app, "manager", "Email/set").await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, _) = request(&app, "GET", "/jmap/session", Some("manager")).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("manager")).await;
	assert_eq!(status, StatusCode::OK, "its own reach stays");
}

#[tokio::test]
async fn mail_write_cannot_create_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "mailer", &["mail:read", "mail:write"]);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some("mailer"),
		Some(json!({})),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("mailer")).await;
	assert_eq!(
		status,
		StatusCode::FORBIDDEN,
		"mail read is not management read"
	);
	let (status, response) = jmap(&app, "mailer", "Email/get").await;
	assert_eq!(status, StatusCode::OK);
	assert!(!is_forbidden(&response), "its own reach stays: {response}");
}

#[tokio::test]
async fn mail_read_cannot_change_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "reader", &["mail:read"]);
	let (status, response) = jmap(&app, "reader", "Email/set").await;
	assert_eq!(status, StatusCode::OK);
	assert!(is_forbidden(&response), "{response}");
}

#[tokio::test]
async fn the_delivery_log_opens_to_mail_and_management_alike() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A key bound to an account reads it under a mail scope, an administrator
	// under a management one, and an unbound key with a mail scope only is
	// neither.
	for (names, account, open) in [
		(&["mail:read"][..], Some("alice"), true),
		(&["manage:read"][..], None, true),
		(&["mail:read"][..], None, false),
	] {
		let app = app_bound(dir.path(), "any", names, account);
		let (status, _) = request(&app, "GET", "/api/v1/deliveries", Some("any")).await;
		assert_eq!(
			status != StatusCode::FORBIDDEN,
			open,
			"{names:?} {account:?}"
		);
		std::fs::remove_file(dir.path().join("api_keys.toml")).expect("reset");
	}
	let app = app_with(dir.path(), "none", &["scim"]);
	let (status, _) = request(&app, "GET", "/api/v1/deliveries", Some("none")).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mail_write_can_set_email() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "mailer", &["mail:write"]);
	let (status, response) = jmap(&app, "mailer", "Email/set").await;
	assert_eq!(status, StatusCode::OK);
	assert!(!is_forbidden(&response), "its own reach: {response}");
}

/// What the coarse check lets a mail scope into for the sake of a key bound to
/// an account is not a way for an unbound key into the lists that are the
/// server's, a tenant's or another account's.
#[tokio::test]
async fn an_unbound_mail_key_cannot_use_the_suppression_lists_or_the_delivery_log() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "mailer", &["mail:read", "mail:write"]);
	let add = json!({ "address": "x@example.net" });
	for path in ["/api/v1/suppression", "/api/v1/suppression?account=alice"] {
		let (status, _) =
			request_with_body(&app, "POST", path, Some("mailer"), Some(add.clone())).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "POST {path}");
	}
	for path in [
		"/api/v1/suppression/x@example.net",
		"/api/v1/suppression/x@example.net?account=alice",
		"/api/v1/suppression/x@example.net?tenant=acme",
	] {
		let (status, _) = request(&app, "DELETE", path, Some("mailer")).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "DELETE {path}");
	}
	for path in [
		"/api/v1/suppression",
		"/api/v1/suppression?account=alice",
		"/api/v1/suppression?tenant=acme",
		"/api/v1/deliveries",
	] {
		let (status, _) = request(&app, "GET", path, Some("mailer")).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "GET {path}");
	}
}

#[tokio::test]
async fn a_key_bound_to_an_account_reaches_that_accounts_list_and_nothing_wider() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_bound(
		dir.path(),
		"alice",
		&["mail:read", "mail:write"],
		Some("alice"),
	);
	let add = json!({ "address": "x@example.net" });
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/suppression?account=alice",
		Some("alice"),
		Some(add.clone()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=alice",
		Some("alice"),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/suppression",
		Some("alice"),
		Some(add),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::FORBIDDEN,
		"the global list is not its own"
	);
}

#[tokio::test]
async fn management_keys_keep_the_lists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app_with(dir.path(), "manager", &["manage:read", "manage:write"]);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/suppression",
		Some("manager"),
		Some(json!({ "address": "x@example.net" })),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	for path in ["/api/v1/suppression", "/api/v1/deliveries"] {
		let (status, _) = request(&app, "GET", path, Some("manager")).await;
		assert_ne!(status, StatusCode::FORBIDDEN, "{path}");
	}
}
