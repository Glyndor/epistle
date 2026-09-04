//! Rolling 24h cap on first-time recipients for `POST /api/v1/send`.
//! The cap is enforced after the per-tenant aggregate rate check and
//! before the spool write, so a refused submission never reaches the
//! spool and leaves the baseline untouched.

use super::tests::{TOKEN, request_with_body};
use super::*;
use crate::storage::FsSpool;
use axum::http::StatusCode;

/// Build an `ApiState` with the correspondent store wired in and a
/// configured daily cap. Mirrors `super::tests::test_state` but with
/// the cap layer attached; re-implementing rather than threading two
/// new arguments through the existing builder keeps the prior tests
/// (which never set the cap) bit-for-bit identical.
fn test_state_with_cap(dir: &std::path::Path, limit: Option<u32>) -> ApiState {
	let spool = FsSpool::open(dir).expect("open spool");
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
	let correspondents = crate::storage::CorrespondentStore::open(dir).expect("correspondents");
	ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle())
	.with_correspondents(correspondents)
	.with_new_recipients_per_day(limit)
}

/// The control: a request whose recipient set would exceed the cap
/// (limit 2, three new recipients) is rejected with `429 rate_limited`
/// and the same sentence the SMTP path returns, so an operator
/// reading either log can correlate by the message.
#[tokio::test]
async fn send_over_the_daily_new_recipient_limit_is_429() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state_with_cap(dir.path(), Some(2)));

	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": [
				"b@elsewhere.example",
				"c@elsewhere.example",
				"d@elsewhere.example",
			],
			"subject": "hi",
			"text": "body"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"]["code"], "rate_limited", "{body}");
	assert!(
		body["error"]["message"]
			.as_str()
			.unwrap_or("")
			.contains("too many new recipients today"),
		"{body}"
	);
	// The refused submission must not have left a queue entry.
	let (_, status_body) =
		request_with_body(&app, "GET", "/api/v1/status", Some(TOKEN.as_str()), None).await;
	assert_eq!(status_body["queue_size"], 0, "{status_body}");
}
