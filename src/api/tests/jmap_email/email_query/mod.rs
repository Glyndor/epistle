//! Email/query contract regressions for #1790. All calls use the HTTP dispatcher.
mod cost;
mod filters;
mod paging;
mod replay;
mod validation;

use crate::api::router;
use crate::api::tests::base::{TOKEN, request_with_body, test_state};
use crate::imap::internal_date::InternalDate;
use crate::imap::mailbox::{self, Flag};
use crate::storage::MessageCrypto;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

const MAIL: &str = "urn:ietf:params:jmap:mail";
const EPOCH: u64 = 1_577_836_800;

async fn envelope(app: &Router, calls: Value) -> Value {
	let req = json!({"using": [MAIL], "methodCalls": calls});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"].clone()
}

async fn call(app: &Router, method: &str, mut args: Value) -> Value {
	if args.get("accountId").is_none() {
		args["accountId"] = json!("alice");
	}
	let responses = envelope(app, json!([[method, args, "c1"]])).await;
	assert_eq!(responses.as_array().expect("responses").len(), 1);
	assert_eq!(responses[0][2], "c1", "{responses}");
	responses[0].clone()
}

async fn query(app: &Router, args: Value) -> Value {
	let response = call(app, "Email/query", args).await;
	assert_eq!(response[0], "Email/query", "{response}");
	response[1].clone()
}

fn error(response: &Value, kind: &str) {
	assert_eq!(response[0], "error", "{response}");
	assert_eq!(response[1]["type"], kind, "{response}");
	assert!(
		response[1].get("ids").is_none(),
		"no partial results: {response}"
	);
}

fn append(dir: &Path, mailbox: &str, seconds: u64, flags: &[Flag], raw: &[u8]) -> String {
	mailbox::append_dated(
		dir,
		"alice",
		mailbox,
		flags,
		Some(InternalDate {
			time: UNIX_EPOCH + Duration::from_secs(seconds),
			zone: 0,
		}),
		raw,
		&MessageCrypto::disabled(),
	)
	.expect("append dated message")
	.to_string()
}

struct Fixture {
	// Retain the directory for the entire router lifetime.
	dir: tempfile::TempDir,
	app: Router,
	old: String,
	middle: String,
	new: String,
}

impl Fixture {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		// Deliberately append out of date order; UUID/arrival order cannot stand in for receivedAt.
		let middle = append(dir.path(), "INBOX", EPOCH + 10, &[],
			b"From: middle@example.org\r\nTo: middle@example.net\r\nSubject: Noise\r\nContent-Type: text/plain\r\n\r\nSenderNeedle ToNeedle SubjectNeedle\r\n");
		let old = append(dir.path(), "INBOX", EPOCH, &[Flag::Seen, Flag::Keyword(crate::imap::keyword::Keyword::new("project").expect("keyword"))],
			b"From: SenderNeedle <first@example.org>\r\nTo: ToNeedle <first@example.net>\r\nCc: CopyNeedle <cc@example.net>\r\nBcc: BlindNeedle <bcc@example.net>\r\nSubject: SubjectNeedle alpha omega O'Reilly\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBodyNeedle\r\n");
		let new = append(dir.path(), "Archive", EPOCH + 20, &[Flag::Flagged],
			b"From: newest@example.org\r\nTo: newest@example.net\r\nSubject: Other\r\n\r\nunrelated\r\n");
		Self {
			dir,
			app,
			old,
			middle,
			new,
		}
	}

	async fn filtered(&self, filter: Value, expected: &[&str]) {
		let response = query(&self.app, json!({"filter": filter})).await;
		assert_eq!(response["ids"], json!(expected), "{response}");
		assert_eq!(response["total"], expected.len(), "{response}");
	}

	async fn page(&self, args: Value, expected: &[&str], position: usize) -> Value {
		let response = query(&self.app, args).await;
		assert_eq!(response["ids"], json!(expected), "{response}");
		assert_eq!(response["position"], position, "{response}");
		response
	}
}
