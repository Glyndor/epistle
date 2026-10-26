//! The framing of a stored message: ambiguous header names and framing are
//! refused before JMAP checks the author or changes the message.

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use crate::storage::FsSpool;
use axum::http::StatusCode;
use std::path::Path;

/// Store `bytes` as a message of alice and submit it. Return the method
/// response and the test directory.
async fn submit(bytes: &[u8]) -> (serde_json::Value, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), bytes).expect("write");
	let state = test_state(dir.path(), 0);
	let outbound = crate::storage::SplitDelivery::new(dir.path(), state.store().handle())
		.expect("outbound routing");
	let app = router(state.with_outbound(std::sync::Arc::new(outbound)));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	(body["methodResponses"][0][1].clone(), dir)
}

/// The one message the spool holds.
fn queued(dir: &Path) -> Vec<u8> {
	let spool = FsSpool::open(dir).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1, "one queued message");
	spool.load(ids[0]).expect("load").data
}

/// Whether the spool holds no message.
fn spool_is_empty(dir: &Path) -> bool {
	FsSpool::open(dir)
		.expect("spool")
		.list()
		.expect("list")
		.is_empty()
}

/// The stored draft the server read.
fn stored_message(dir: &Path) -> Vec<u8> {
	let inbox = dir.join("accounts").join("alice").join("new");
	for entry in std::fs::read_dir(inbox).expect("inbox") {
		let entry = entry.expect("entry");
		if entry.path().extension().and_then(|name| name.to_str()) == Some("eml") {
			return std::fs::read(entry.path()).expect("stored message");
		}
	}
	panic!("stored message");
}

/// A carriage return that is not followed by a line feed makes the header
/// framing ambiguous. JMAP refuses the message before it reaches the spool.
#[tokio::test]
async fn a_loose_cr_is_refused() {
	let stored = b"From: alice@example.org\r\n\
		\rX-Epistle-Attachment-Warning: forged\r\n\
		Authentication-Results: forged.example; dkim=pass\r\n\
		Subject: s\r\n\
		\r\n\
		body\r\n";
	let (response, dir) = submit(stored).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "forbiddenToSend",
		"{response}"
	);
	let description = response["notCreated"]["s1"]["description"]
		.as_str()
		.unwrap_or_default();
	assert!(description.contains("bare carriage return"), "{response}");
	assert!(spool_is_empty(dir.path()), "{response}");
}

/// A CRCRLF boundary is ambiguous too. The stored draft stays unchanged and
/// no queued copy is made.
#[tokio::test]
async fn a_crcrlf_boundary_is_refused_without_changing_the_body() {
	let stored = b"From: alice@example.org\r\n\
		Subject: s\r\n\
		\r\r\n\
		List-Unsubscribe: this is body text\r\n\
		X-Epistle: body text\r\n\
		Authentication-Results: body text\r\n";
	let (response, dir) = submit(stored).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "forbiddenToSend",
		"{response}"
	);
	let description = response["notCreated"]["s1"]["description"]
		.as_str()
		.unwrap_or_default();
	assert!(description.contains("bare carriage return"), "{response}");
	assert!(spool_is_empty(dir.path()), "{response}");
	assert_eq!(
		stored_message(dir.path()),
		stored,
		"the stored body changed"
	);
}

/// A second From whose name carries whitespace is refused before the
/// author check can accept the ordinary From alone.
#[tokio::test]
async fn a_spaced_second_from_is_refused() {
	let stored = b"From: alice@example.org\r\n\
		Fr om: victim@elsewhere.example\r\n\
		Subject: s\r\n\
		\r\n\
		body\r\n";
	let (response, dir) = submit(stored).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "forbiddenToSend",
		"{response}"
	);
	let description = response["notCreated"]["s1"]["description"]
		.as_str()
		.unwrap_or_default();
	assert!(description.contains("field names"), "{response}");
	assert!(spool_is_empty(dir.path()), "{response}");
}

/// A field-looking line after the real blank line is body text. It is
/// neither rejected nor changed.
#[tokio::test]
async fn a_list_unsubscribe_after_the_real_blank_line_is_left_in_the_body() {
	let body = b"List -Unsubscribe: texto\r\n";
	let mut stored = b"From: alice@example.org\r\nSubject: s\r\n\r\n".to_vec();
	stored.extend_from_slice(body);
	let (response, dir) = submit(&stored).await;
	assert!(response["created"]["s1"]["id"].is_string(), "{response}");
	let queued = queued(dir.path());
	assert!(queued.ends_with(body), "the queued body changed");
}

#[tokio::test]
async fn malformed_header_lines_are_refused() {
	for stored in [
		b" From: victim@elsewhere.example\r\nFrom: alice@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: alice@example.org\r\n:From: victim@elsewhere.example\r\n\r\nbody\r\n".as_slice(),
		b"From: alice@example.org\r\nGarbage\r\n Fr om: victim@elsewhere.example\r\n\r\nbody\r\n"
			.as_slice(),
	] {
		let (response, dir) = submit(stored).await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenToSend",
			"{response}"
		);
		assert_eq!(
			response["notCreated"]["s1"]["description"],
			"submission header lines must follow RFC 5322 field and folding syntax",
			"{response}"
		);
		assert!(spool_is_empty(dir.path()), "{response}");
	}
}

#[tokio::test]
async fn an_lf_only_message_is_accepted() {
	let stored = b"From: alice@example.org\nSubject: s\n\nbody\n";
	let (response, dir) = submit(stored).await;
	assert!(response["created"]["s1"]["id"].is_string(), "{response}");
	let queued = queued(dir.path());
	for (index, byte) in queued.iter().enumerate() {
		if *byte == b'\n' {
			assert!(
				index > 0 && queued[index - 1] == b'\r',
				"I found a bare LF in the queued message"
			);
		}
	}
	assert!(
		queued.ends_with(b"\r\n\r\nbody\r\n"),
		"I expect the same body with CRLF endings"
	);
}

#[tokio::test]
async fn a_body_after_a_leading_blank_line_is_not_a_header_block() {
	for stored in [
		b"\r\nHello world: x\r\n".as_slice(),
		b"\nHello world: x\n".as_slice(),
	] {
		let (response, dir) = submit(stored).await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenFrom",
			"{response}"
		);
		assert!(spool_is_empty(dir.path()), "{response}");
	}
}

#[tokio::test]
async fn reader_disagreement_and_invalid_encoding_are_refused_before_the_author_check() {
	for (stored, expected) in [
		(b"From: alice@example.org\r\nDate: Mon, 1 Jan 2020 00:00:00 -0500x\r\n\r\nFrom: victim@example.net\r\n".as_slice(), "I cannot accept headers whose From or Sender field counts disagree between readers"),
		(b"From: alice@example.org\r\nSubject: caf\xe9\r\n\r\nx".as_slice(), "I cannot accept submission headers that are not UTF-8"),
	] {
		let (response, dir) = submit(stored).await;
		assert_eq!(response["notCreated"]["s1"]["type"], "forbiddenToSend", "{response}");
		assert_eq!(response["notCreated"]["s1"]["description"], expected, "{response}");
		assert!(spool_is_empty(dir.path()));
		assert_eq!(stored_message(dir.path()), stored);
	}
}

/// A carriage return or a NUL in the body is refused too, whatever the
/// headers look like, so nothing with loose framing reaches the spool.
#[tokio::test]
async fn a_loose_cr_or_nul_in_the_body_is_refused() {
	for body in [
		b"hello\r.\r\nmore\r\n".as_slice(),
		b"body\r".as_slice(),
		b"bo\0dy\r\n".as_slice(),
	] {
		let mut stored = b"From: alice@example.org\r\nSubject: s\r\n\r\n".to_vec();
		stored.extend_from_slice(body);
		let (response, dir) = submit(&stored).await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenToSend",
			"{response}"
		);
		assert!(spool_is_empty(dir.path()), "{response}");
	}
}
