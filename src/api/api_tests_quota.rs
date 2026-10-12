//! `POST /api/v1/send` and `EmailSubmission/set` refuse a local recipient
//! whose mailbox is full, or would be by this message, with a clear error
//! and nothing queued: the same measure IMAP QUOTA reports.

use super::tests::{TOKEN, request_with_body};
use super::*;
use crate::storage::{FsSpool, MessageCrypto};
use axum::http::StatusCode;

/// alice has no quota of her own; bob has 64 bytes.
fn state(dir: &std::path::Path) -> ApiState {
	let account = |name: &str, quota_bytes: Option<u64>| crate::config::Account {
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			vec![account("alice", None), account("bob", Some(64))],
		)
		.expect("open store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		FsSpool::open(dir).expect("spool"),
	)
	.with_directory(store.handle())
}

/// Store `bytes` bytes of mail in bob's INBOX.
fn fill_bob(dir: &std::path::Path, bytes: usize) {
	crate::imap::mailbox::append(
		dir,
		"bob",
		"INBOX",
		&[],
		&vec![b'x'; bytes],
		&MessageCrypto::disabled(),
	)
	.expect("append");
}

fn queued(dir: &std::path::Path) -> usize {
	FsSpool::open(dir)
		.expect("spool")
		.list()
		.expect("list")
		.len()
}

async fn send_to(app: &axum::Router, to: &str) -> (StatusCode, serde_json::Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": [to],
			"subject": "hi",
			"text": "body"
		})),
	)
	.await
}

#[tokio::test]
async fn a_send_to_a_full_local_mailbox_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	fill_bob(dir.path(), 64);
	let app = router(state(dir.path()));

	let (status, body) = send_to(&app, "bob@example.org").await;

	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");
	assert_eq!(body["error"]["code"], "mailbox_full", "{body}");
	assert!(
		body["error"]["message"]
			.as_str()
			.unwrap_or_default()
			.contains("bob@example.org"),
		"{body}"
	);
	assert_eq!(queued(dir.path()), 0, "nothing queued");
}

#[tokio::test]
async fn a_send_that_would_overfill_a_local_mailbox_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	fill_bob(dir.path(), 20);
	let app = router(state(dir.path()));

	// The message (headers and all) is well over the 44 bytes left.
	let (status, body) = send_to(&app, "bob@example.org").await;

	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");
	assert_eq!(queued(dir.path()), 0);
}

#[tokio::test]
async fn a_send_within_quota_is_queued() {
	let dir = tempfile::tempdir().expect("tempdir");
	fill_bob(dir.path(), 64);
	let app = router(state(dir.path()));

	let (status, body) = send_to(&app, "alice@example.org").await;

	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(queued(dir.path()), 1);
}

#[tokio::test]
async fn a_jmap_submission_to_a_full_local_mailbox_is_over_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	fill_bob(dir.path(), 64);
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@example.org\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(state(dir.path()));

	let request = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@example.org"}]},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(request),
	)
	.await;

	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["notCreated"]["s1"]["type"], "overQuota",
		"{body}"
	);
	assert_eq!(queued(dir.path()), 0);
}
