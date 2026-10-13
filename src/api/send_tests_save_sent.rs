//! Tests for the `/api/v1/send` save-sent integration.
//!
//! The request may carry `"save_sent": false` to skip the Sent
//! copy; otherwise the copy lands when the account-wide setting
//! admits it.

use axum::http::StatusCode;
use serde_json::json;

use super::router;
use super::send_tests_outbound::routed_state;
use super::tests::{TOKEN, request_with_body};
use crate::storage::FsSpool;

#[tokio::test]
async fn api_send_with_save_sent_off_does_not_write_to_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(routed_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"text": "hi",
			"save_sent": false,
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let stored = std::fs::read_dir(dir.path().join("accounts").join("alice"))
		.map(|entries| {
			entries
				.flatten()
				.filter(|entry| entry.path().is_file())
				.filter(|entry| {
					entry
						.path()
						.extension()
						.is_some_and(|ext| ext == "eml")
				})
				.count()
		})
		.unwrap_or(0);
	assert_eq!(
		stored, 0,
		"save_sent: false keeps the Sent copy off disk; no local recipient"
	);
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list").len(),
		1,
		"the message still left the server"
	);
}

#[tokio::test]
async fn api_send_with_save_sent_unset_stores_a_copy_in_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(routed_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"text": "hi",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let sent = std::fs::read_dir(
		dir.path()
			.join("accounts")
			.join("alice")
			.join("folders")
			.join("Sent")
			.join("new"),
	)
	.expect("Sent exists")
	.flatten()
	.filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
	.count();
	assert_eq!(sent, 1, "default-on stores the Sent copy");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list").len(),
		1,
		"the spool still has the outbound copy"
	);
}

#[tokio::test]
async fn api_send_with_save_sent_off_still_keeps_the_outbound_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(routed_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"text": "hi",
			"save_sent": false,
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	// No local recipient: the spool holds the outbound copy,
	// nothing on disk under the account.
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list").len(),
		1,
		"the outbound spool still has the message"
	);
	let on_disk = std::fs::read_dir(dir.path().join("accounts").join("alice"))
		.map(|entries| {
			entries
				.flatten()
				.filter(|entry| entry.path().is_file())
				.filter(|entry| {
					entry
						.path()
						.extension()
						.is_some_and(|ext| ext == "eml")
				})
				.count()
		})
		.unwrap_or(0);
	assert_eq!(on_disk, 0, "no Sent copy: the request opted out");
}