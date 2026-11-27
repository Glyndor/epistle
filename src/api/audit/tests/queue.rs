//! The removal of a queued message: what the audit says about it.
//!
//! The line names the message, the account that sent it and the key that
//! asked for it to go. It never names the recipients, the subject, or the
//! key itself.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use uuid::Uuid;

use crate::api::ApiState;
use crate::api::router;
use crate::api::tests::base::{TOKEN, request, test_state};
use crate::smtp::session::AcceptedMessage;

use super::base::{audit_blob, audit_events, run_with_capture};

/// The message the queue holds. Nothing of it may reach the audit line.
const MESSAGE: &str = "Subject: quarterly figures\r\nFrom: <alice@example.org>\r\n\r\nthe body\r\n";

/// A message in the queue, sent by `account`.
fn queued(state: &ApiState, account: &str) -> Uuid {
	state
		.spool()
		.store(
			&AcceptedMessage {
				reverse_path: format!("{account}@example.org"),
				recipients: vec!["bob@remote.example".to_string()],
				data: MESSAGE.as_bytes().to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			Some(account),
			&BTreeMap::new(),
		)
		.expect("store")
}

/// Removing a message writes one line: the id of the message, the account
/// that sent it, the key that asked and the client address. The message
/// itself is not in it.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_queued_message_writes_one_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let id = queued(&state, "alice");
	let app = router(state);

	let events = run_with_capture(async {
		let (status, body) = request(
			&app,
			"DELETE",
			&format!("/api/v1/queue/{id}"),
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("event").map(String::as_str),
		Some("queue.removed")
	);
	let id_text = id.to_string();
	assert_eq!(
		audit[0].fields.get("id").map(String::as_str),
		Some(id_text.as_str())
	);
	assert_eq!(
		audit[0].fields.get("account").map(String::as_str),
		Some(crate::log_id::account("alice").as_str()),
		"the account is named by its pseudonym"
	);
	assert_eq!(
		audit[0].fields.get("key").map(String::as_str),
		Some("configured-token")
	);
	assert_eq!(
		audit[0].fields.get("client_ip").map(String::as_str),
		Some("unknown"),
		"no ConnectInfo in tests -> unknown"
	);

	let blob = audit_blob(&events);
	assert!(
		!blob.contains("bob@remote.example"),
		"the audit carried a recipient: {blob}"
	);
	assert!(
		!blob.contains("quarterly figures"),
		"the audit carried the subject: {blob}"
	);
	assert!(
		!blob.contains(TOKEN.as_str()),
		"the audit leaked the bearer: {blob}"
	);
}

/// The line names the key by its label, never by the key itself.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_names_the_key_by_its_label() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = "the-remover-key-secret";
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(crate::api::ApiKey {
		grants: Vec::new(),
		label: "remover".to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![
			crate::api::api_keys::Scope::ManageWrite
				.as_str()
				.to_string(),
		],
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
	drop(keys);
	let state = test_state(dir.path(), 0);
	let id = queued(&state, "alice");
	let app = router(state);

	let events = run_with_capture(async {
		let (status, body) =
			request(&app, "DELETE", &format!("/api/v1/queue/{id}"), Some(secret)).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	});

	let audit = audit_events(&events);
	assert_eq!(
		audit.len(),
		1,
		"exactly one audit event expected: {events:?}"
	);
	assert_eq!(
		audit[0].fields.get("key").map(String::as_str),
		Some("remover")
	);
	let blob = audit_blob(&events);
	assert!(!blob.contains(secret), "the audit leaked the key: {blob}");
}

/// A removal that was refused writes no line: there was no change to
/// record.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_removal_writes_no_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let app = router(state);
	let missing = Uuid::now_v7();

	let events = run_with_capture(async {
		let (status, body) = request(
			&app,
			"DELETE",
			&format!("/api/v1/queue/{missing}"),
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	});

	assert!(
		audit_events(&events).is_empty(),
		"a refused removal wrote a line: {events:?}"
	);
}
