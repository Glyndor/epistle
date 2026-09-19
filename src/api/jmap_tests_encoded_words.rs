//! JMAP and RFC 2047: `Email/get` decodes encoded-words in the subject and in
//! display names, and `Email/set` writes non-ASCII values as encoded-words.

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use axum::http::StatusCode;

/// Same guard as `jmap_email_set_sanitises_header_injection_in_subject`
/// but for a non-ASCII subject: the sanitiser has to run BEFORE the
/// RFC 2047 encoder so a CRLF in the user's text never lands inside an
/// encoded-word and breaks out as a fresh header line on the wire.
#[tokio::test]
async fn jmap_email_set_sanitises_header_injection_in_non_ascii_subject() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// The CRLF + Bcc payload rides inside what would otherwise be the
	// encoded-word; if encoding ran on the raw value, the Bcc would land
	// on its own line after the encoding pipeline.
	let req = serde_json::json!({
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"create": { "d2": {
				"mailboxIds": {"INBOX": true},
				"from": [{"email": "alice@example.org"}],
				"to": [{"email": "alice@example.org"}],
				"subject": "Reunión\r\nBcc: attacker@evil.example",
			} },
		}, "c1"]],
	});
	let (status, _body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let find_message = |dir: &std::path::Path| -> Option<Vec<u8>> {
		let entries = std::fs::read_dir(dir).ok()?;
		for entry in entries.flatten() {
			if let Ok(bytes) = std::fs::read(entry.path()) {
				return Some(bytes);
			}
		}
		None
	};
	let raw = find_message(&dir.path().join("accounts").join("alice").join("cur"))
		.or_else(|| find_message(&dir.path().join("accounts").join("alice").join("new")))
		.expect("stored message");
	let text = String::from_utf8_lossy(&raw);
	for line in text.lines() {
		assert!(
			!line.to_ascii_lowercase().starts_with("bcc:"),
			"forged Bcc: must not appear as its own header: {line:?}"
		);
	}
	let subject_line = text
		.lines()
		.find(|line| line.to_ascii_lowercase().starts_with("subject:"))
		.expect("subject header");
	assert!(
		!subject_line.contains('\r') && !subject_line.contains('\n'),
		"Subject: line must not contain CRLF: {subject_line:?}"
	);
}

/// `Email/get` decodes the `Subject:` and the `name` of every address
/// through the RFC 2047 decoder so a JMAP client sees the original
/// characters, not the encoded-word bytes. The decoder runs AFTER the
/// address list is split, so an encoded-word cannot inject a second
/// address.
#[tokio::test]
async fn jmap_email_get_decodes_encoded_subject_and_address_names() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let raw = b"\
Subject: =?UTF-8?B?wqFIb2xhIQ==?= \r\n\
From: =?UTF-8?Q?Jos=C3=A9_P=C3=A9rez?= <jose@example.org>\r\n\
\r\n\
body\r\n";
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": [id.to_string()]}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let email = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(email["subject"], "\u{00a1}Hola!");
	assert_eq!(email["from"][0]["email"], "jose@example.org");
	assert_eq!(email["from"][0]["name"], "Jos\u{00e9} P\u{00e9}rez");
}

/// The address parser splits the address list BEFORE decoding the
/// display name: an encoded-word whose decoded form contains `<`, `>` or
/// `,` keeps those characters as data. The hostile `From:` here decodes
/// to a string with `<evil@example.net>` inside the name, but the
/// parser only saw the original encoded-word delimiter and recognised
/// one address: `real@example.org`.
#[tokio::test]
async fn jmap_email_get_address_injection_via_encoded_word_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let raw = b"\
From: =?UTF-8?Q?a=3E=2C_=3Cevil=40example=2Enet?= <real@example.org>\r\n\
\r\n\
body\r\n";
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": [id.to_string()]}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let email = &body["methodResponses"][0][1]["list"][0];
	let from = email["from"].as_array().expect("from array");
	assert_eq!(from.len(), 1, "exactly one address must survive parsing");
	assert_eq!(from[0]["email"], "real@example.org");
	assert_eq!(from[0]["name"], "a>, <evil@example.net");
}

/// Round-trip for `Email/set` create followed by `Email/get`: the client
/// submits a non-ASCII subject, the stored message carries it as one or
/// more RFC 2047 B-encoded-words (ASCII-clean), and the subsequent `get`
/// decodes the words back to the original characters.
#[tokio::test]
async fn jmap_email_set_round_trips_non_ascii_subject() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"create": { "d3": {
				"mailboxIds": {"INBOX": true},
				"from": [{"email": "alice@example.org"}],
				"to": [{"email": "alice@example.org"}],
				"subject": "Reuni\u{00f3}n ma\u{00f1}ana",
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let id = body["methodResponses"][0][1]["created"]["d3"]["id"]
		.as_str()
		.expect("created id")
		.to_string();
	// Pull the stored message back. Append goes to `INBOX/cur` after
	// delivery (delivery moves it from `new`).
	let find_message = |dir: &std::path::Path| -> Option<Vec<u8>> {
		let entries = std::fs::read_dir(dir).ok()?;
		for entry in entries.flatten() {
			if let Ok(bytes) = std::fs::read(entry.path()) {
				return Some(bytes);
			}
		}
		None
	};
	let raw = find_message(&dir.path().join("accounts").join("alice").join("cur"))
		.or_else(|| find_message(&dir.path().join("accounts").join("alice").join("new")))
		.expect("stored message");
	let text = String::from_utf8_lossy(&raw);
	let subject_line = text
		.lines()
		.find(|line| line.to_ascii_lowercase().starts_with("subject:"))
		.expect("subject header");
	// The stored Subject: line is pure ASCII (the encoded-word is the
	// only thing that contains non-ASCII, and only inside the base64).
	let payload = subject_line
		.strip_prefix("Subject: ")
		.or_else(|| subject_line.strip_prefix("subject: "))
		.unwrap_or(subject_line);
	assert!(
		payload.is_ascii(),
		"Subject: line must be pure ASCII on disk: {payload:?}"
	);
	// Read it back through JMAP `Email/get`: the subject is the original.
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": [id]}, "c2"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let email = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(email["subject"], "Reuni\u{00f3}n ma\u{00f1}ana");
}
