use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;
use std::sync::LazyLock;
use std::time::Duration;

// The bearer token used by every API test is generated fresh at startup. A literal
// bound to a constant named TOKEN triggered CodeQL `rust/hard-coded-cryptographic-value`.
pub(super) static TOKEN: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

fn sha256_hash(token: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	format!("sha256:{hex}")
}

pub(super) fn test_state(dir: &std::path::Path, queued: usize) -> ApiState {
	let spool = FsSpool::open(dir).expect("open spool");
	for i in 0..queued {
		spool
			.store(&AcceptedMessage {
				reverse_path: format!("a{i}@example.org"),
				recipients: vec![format!("r{i}@elsewhere.example")],
				data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				no_dsn: Vec::new(),
			})
			.expect("store");
	}
	let accounts = vec![crate::config::Account {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle())
}

pub(super) async fn request(
	app: &Router,
	method: &str,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
	request_with_body(app, method, path, token, None).await
}

pub(super) async fn request_with_body(
	app: &Router,
	method: &str,
	path: &str,
	token: Option<&str>,
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	let mut builder = Request::builder().method(method).uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let body = match body {
		Some(json) => {
			builder = builder.header(header::CONTENT_TYPE, "application/json");
			Body::from(json.to_string())
		}
		None => Body::empty(),
	};
	let response = app
		.clone()
		.oneshot(builder.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json = if bytes.is_empty() {
		serde_json::Value::Null
	} else {
		serde_json::from_slice(&bytes).expect("json body")
	};
	(status, json)
}

/// Like `request`, but returns the raw response body (for non-JSON endpoints).
pub(super) async fn request_raw(
	app: &Router,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
	let mut builder = Request::builder().method("GET").uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec())
}

#[tokio::test]
async fn requests_without_token_are_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/status", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(body["error"]["code"], "unauthenticated");

	let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn healthz_is_unauthenticated() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// Liveness probe needs no token.
	let (status, _) = request(&app, "GET", "/healthz", None).await;
	assert_eq!(status, StatusCode::OK);
	// The authenticated surface still rejects tokenless requests.
	let (status, _) = request(&app, "GET", "/api/v1/status", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_reports_counts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 2));
	let (status, body) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["domains"], 1);
	assert_eq!(body["accounts"], 1);
	assert_eq!(body["queue_size"], 2);
}

#[tokio::test]
async fn accounts_never_expose_credentials() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["accounts"][0]["name"], "alice");
	assert!(!body.to_string().contains("argon2"), "{body}");
}

#[tokio::test]
async fn domains_are_listed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/domains", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["domains"][0], "example.org");
}

#[tokio::test]
async fn queue_pagination_walks_all_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 5));

	let (status, page) = request(&app, "GET", "/api/v1/queue?limit=2", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(page["entries"].as_array().expect("entries").len(), 2);
	let cursor = page["next_cursor"].as_str().expect("cursor").to_string();

	let (_, page2) = request(
		&app,
		"GET",
		&format!("/api/v1/queue?limit=2&cursor={cursor}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(page2["entries"].as_array().expect("entries").len(), 2);
	// No overlap between pages.
	assert_ne!(page["entries"][0]["id"], page2["entries"][0]["id"]);

	let cursor2 = page2["next_cursor"].as_str().expect("cursor").to_string();
	let (_, page3) = request(
		&app,
		"GET",
		&format!("/api/v1/queue?limit=2&cursor={cursor2}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(page3["entries"].as_array().expect("entries").len(), 1);
	assert!(page3["next_cursor"].is_null());
}

#[tokio::test]
async fn queue_rejects_zero_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/queue?limit=0", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"]["code"], "invalid_input");
}

#[tokio::test]
async fn queue_entry_can_be_removed_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 1));
	let (_, page) = request(&app, "GET", "/api/v1/queue", Some(TOKEN.as_str())).await;
	let id = page["entries"][0]["id"].as_str().expect("id").to_string();

	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["removed"], id.as_str());

	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn unknown_route_is_404() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request(&app, "GET", "/api/v1/nope", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sha256_token_format_is_accepted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![],
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&sha256_hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		vec![],
		store.clone(),
		spool,
	)
	.with_directory(store.handle());
	let app = router(state);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mailboxes_lists_inbox_for_known_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/alice/mailboxes",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let mailboxes = body["mailboxes"].as_array().expect("mailboxes");
	assert!(mailboxes.iter().any(|m| m == "INBOX"), "{body}");
}

#[tokio::test]
async fn mailboxes_returns_404_for_unknown_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/accounts/nobody/mailboxes",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn send_enqueues_and_validates() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	// A valid request enqueues the message.
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(body["queued"].as_str().is_some(), "{body}");
	let (_, status_body) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(status_body["queue_size"], 1);

	// Empty recipients, CR/LF header injection, a bad address, and an over-long
	// recipient list (> MAX_RECIPIENTS) are all rejected.
	let many: Vec<String> = (0..200).map(|i| format!("r{i}@x.example")).collect();
	for bad in [
		serde_json::json!({"from": "alice@example.org", "to": []}),
		serde_json::json!({"from": "alice@example.org", "to": ["b@x.example"], "subject": "x\r\nBcc: evil@x"}),
		serde_json::json!({"from": "not-an-address", "to": ["b@x.example"]}),
		serde_json::json!({"from": "alice@example.org", "to": many}),
	] {
		let (status, body) = request_with_body(
			&app,
			"POST",
			"/api/v1/send",
			Some(TOKEN.as_str()),
			Some(bad),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST);
		assert_eq!(body["error"]["code"], "invalid_input");
	}
}

#[tokio::test]
async fn rate_limit_triggers_after_repeated_failures() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The wall clock under a loaded parallel run is not the thing under test
	// here; the limiter's window logic is covered by `state_limiter_tests.rs`.
	// Stretch the window so the 21 calls cannot span it.
	let app = router(test_state(dir.path(), 0).with_auth_window(Duration::from_secs(3600)));
	for _ in 0..20 {
		let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
	}
	let (status, body) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn suppression_lists_global_and_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("open");
	suppression.suppress("bob@example.net");
	suppression.suppress_for("alice@example.org", "carol@example.net");
	let app = router(test_state(dir.path(), 0));

	// Global list.
	let (status, body) = request(&app, "GET", "/api/v1/suppression", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "bob@example.net");

	// Per-account list.
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=alice@example.org",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "carol@example.net");
}

#[tokio::test]
async fn suppression_delete_removes_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("open");
	suppression.suppress("bob@example.net");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/suppression/bob@example.net",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["removed"], "bob@example.net");
	assert!(
		!crate::queue::SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}
