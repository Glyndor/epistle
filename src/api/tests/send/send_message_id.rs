//! The answer to `POST /api/v1/send` names the `Message-ID` the server wrote,
//! so a caller can thread a reply or find the message without reading the
//! queue.

use super::base::{TOKEN, request_with_body};
use super::router;
use super::send_outbound::{alice_messages, routed_state};
use super::send_rich::{queued, send};
use crate::storage::FsSpool;
use axum::http::StatusCode;
use mail_parser::MessageParser;
use serde_json::json;

/// The `Message-ID` of `raw`, in angle brackets the way a header writes it.
fn header_id(raw: &[u8]) -> String {
	let message = MessageParser::default().parse(raw).expect("parse");
	format!("<{}>", message.message_id().expect("Message-ID header"))
}

#[tokio::test]
async fn the_answer_names_the_message_id_the_queued_message_carries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"text": "hello"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	let id = body["message_id"].as_str().expect("message_id is a string");
	assert_eq!(id, header_id(&raw));
	assert!(
		String::from_utf8_lossy(&raw).contains(&format!("Message-ID: {id}\r\n")),
		"the header carries the value as the answer gave it"
	);
}

#[tokio::test]
async fn the_id_is_one_bracketed_token_on_the_domain_of_the_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"text": "hello"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let id = body["message_id"].as_str().expect("message_id");
	let inner = id
		.strip_prefix('<')
		.and_then(|rest| rest.strip_suffix('>'))
		.expect("angle brackets");
	let (local, domain) = inner.split_once('@').expect("one at sign");
	assert_eq!(domain, "example.org");
	assert!(uuid::Uuid::parse_str(local).is_ok(), "{local}");
	assert!(!id.chars().any(|c| c.is_whitespace() || c.is_control()));
}

#[tokio::test]
async fn every_send_gets_its_own_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (_, first) = send(dir.path(), json!({"text": "same"})).await;
	let (_, second) = send(dir.path(), json!({"text": "same"})).await;
	assert_ne!(first["message_id"], second["message_id"]);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let mut written: Vec<String> = spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| header_id(&spool.load(id).expect("load").data))
		.collect();
	written.sort();
	let mut answered: Vec<String> = [&first, &second]
		.iter()
		.map(|body| body["message_id"].as_str().expect("message_id").to_owned())
		.collect();
	answered.sort();
	assert_eq!(written, answered, "each answer matches one queued message");
}

#[tokio::test]
async fn the_request_cannot_choose_the_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"text": "x", "message_id": "<chosen@attacker.example>"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_ne!(body["message_id"], "<chosen@attacker.example>");
	let (_, raw) = queued(dir.path());
	assert!(!String::from_utf8_lossy(&raw).contains("attacker.example"));
	// A header in `headers` cannot replace it either.
	let other = tempfile::tempdir().expect("tempdir");
	let (status, _) = send(
		other.path(),
		json!({"text": "x", "headers": {"Message-ID": "<chosen@attacker.example>"}}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_id_threads_a_reply() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (_, first) = send(dir.path(), json!({"text": "first"})).await;
	let id = first["message_id"].as_str().expect("message_id").to_owned();
	let other = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		other.path(),
		json!({"text": "reply", "in_reply_to": id, "references": id}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(other.path());
	let text = String::from_utf8_lossy(&raw);
	assert!(text.contains(&format!("In-Reply-To: {id}\r\n")), "{text}");
	assert!(text.contains(&format!("References: {id}\r\n")), "{text}");
}

#[tokio::test]
async fn a_refused_request_names_no_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"from": "nobody@elsewhere.example", "text": "x"}),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(body.get("message_id").is_none(), "{body}");
	let (status, body) = send(dir.path(), json!({"to": [], "text": "x"})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert!(body.get("message_id").is_none(), "{body}");
}

#[tokio::test]
async fn a_local_recipient_finds_the_same_id_in_its_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({"from": "alice@example.org", "to": ["alice@example.org"], "text": "x"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let id = body["message_id"].as_str().expect("message_id");
	let delivered: Vec<Vec<u8>> = alice_messages(dir.path())
		.into_iter()
		.filter(|raw| String::from_utf8_lossy(raw).contains("Return-Path:"))
		.collect();
	assert_eq!(delivered.len(), 1);
	assert_eq!(header_id(&delivered[0]), id);
}
