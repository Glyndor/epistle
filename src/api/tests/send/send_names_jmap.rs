//! The same display name gets the same bytes in `To` from `POST
//! /api/v1/send` and from JMAP `Email/set`, and the same limits: a name
//! `from_name` would refuse is refused by both.

use super::outbound::send_outbound::alice_messages;
use super::send_rich::{queued, send};
use crate::api::tests::jmap_email::jmap_email_create::create;
use axum::http::StatusCode;
use serde_json::json;

/// The `To:` line of `raw`, unfolded.
fn to_line(raw: &[u8]) -> String {
	let text = String::from_utf8(raw.to_vec()).expect("ASCII headers");
	let head = text.split("\r\n\r\n").next().expect("head");
	head.replace("\r\n ", " ")
		.lines()
		.find(|l| l.starts_with("To: "))
		.expect("To header")
		.to_string()
}

const NAMES: [&str; 7] = [
	"Ana Perez",
	"Ana Pérez",
	"Doe, Jane",
	"Jane \"JJ\" Doe",
	r"Jane \ Doe",
	"Jane (Ops) <team>",
	"日本語の名前",
];

#[tokio::test]
async fn both_paths_write_the_same_header_for_the_same_name() {
	for name in NAMES {
		let api_dir = tempfile::tempdir().expect("tempdir");
		let (status, body) = send(
			api_dir.path(),
			json!({"to": [{"name": name, "address": "bob@elsewhere.example"}], "text": "x"}),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{name}: {body}");
		let (_, api_raw) = queued(api_dir.path());

		let jmap_dir = tempfile::tempdir().expect("tempdir");
		let app = super::router(super::super::base::test_state(jmap_dir.path(), 0));
		let response = create(
			&app,
			json!({"to": [{"name": name, "email": "bob@elsewhere.example"}]}),
		)
		.await;
		assert!(
			response["created"]["e"]["id"].is_string(),
			"{name}: {response}"
		);
		let stored = alice_messages(jmap_dir.path());
		assert_eq!(stored.len(), 1, "{name}");
		assert_eq!(to_line(&api_raw), to_line(&stored[0]), "{name}");
	}
}

#[tokio::test]
async fn both_paths_refuse_the_names_from_name_refuses() {
	for name in ["Ana\r\nBcc: v@e.example", "a\u{0}b", &"x".repeat(129)] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (status, _) = send(
			dir.path(),
			json!({"to": [{"name": name, "address": "bob@elsewhere.example"}], "text": "x"}),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "api: {name:?}");

		let app = super::router(super::super::base::test_state(dir.path(), 0));
		let response = create(
			&app,
			json!({"to": [{"name": name, "email": "bob@elsewhere.example"}]}),
		)
		.await;
		assert_eq!(
			response["notCreated"]["e"]["type"], "invalidProperties",
			"jmap: {name:?}: {response}"
		);
		assert!(alice_messages(dir.path()).is_empty(), "{name:?}");
	}
}
