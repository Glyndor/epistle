//! A recipient of `POST /api/v1/send` is a bare address or an object with a
//! display name. The name is a phrase in `To`, `Cc` and `Reply-To`, written
//! the way `from_name` is, and never in `Bcc` or on the envelope.

use super::send_rich::{queued, send};
use crate::storage::FsSpool;
use axum::http::StatusCode;
use mail_parser::MessageParser;
use serde_json::{Value, json};

fn named(name: &str, address: &str) -> Value {
	json!({"name": name, "address": address})
}

/// The raw header lines of `raw`, unfolded, as written.
fn header_block(raw: &[u8]) -> String {
	let text = String::from_utf8(raw.to_vec()).expect("headers are ASCII");
	let head = text.split("\r\n\r\n").next().expect("head");
	head.to_string()
}

/// The unfolded `name: value` line of `header` in `raw`.
fn line(raw: &[u8], header: &str) -> String {
	let block = header_block(raw).replace("\r\n ", " ");
	let prefix = format!("{header}: ");
	block
		.lines()
		.find(|l| l.starts_with(&prefix))
		.unwrap_or_else(|| panic!("no {header} in {block}"))
		.to_string()
}

/// Every `(name, address)` of the address header `which`, read by the
/// MIME parser the server uses for what it receives.
fn parsed(raw: &[u8], which: &str) -> Vec<(Option<String>, String)> {
	let message = MessageParser::default().parse(raw).expect("parse");
	let list = match which {
		"To" => message.to(),
		"Cc" => message.cc(),
		_ => message.reply_to(),
	}
	.expect("address header");
	list.mailboxes()
		.map(|m| {
			(
				m.name().map(str::to_string),
				m.address().expect("address").to_string(),
			)
		})
		.collect()
}

async fn sent(extra: Value) -> (Vec<String>, Vec<u8>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), extra).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	queued(dir.path())
}

async fn refused(extra: Value) -> Value {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), extra).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input", "{body}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "nothing queued");
	body
}

#[tokio::test]
async fn a_plain_string_is_written_as_the_bare_address() {
	let (rcpt, raw) = sent(json!({"to": ["Ana@Elsewhere.Example"], "text": "x"})).await;
	assert_eq!(rcpt, vec!["ana@elsewhere.example"]);
	assert_eq!(line(&raw, "To"), "To: ana@elsewhere.example");
}

#[tokio::test]
async fn an_object_writes_the_name_in_front_of_the_address() {
	let (rcpt, raw) = sent(json!({
		"to": [named("Ana Perez", "ana@elsewhere.example"), "bob@elsewhere.example"],
		"cc": [named("Carol", "carol@elsewhere.example")],
		"reply_to": named("Help Desk", "help@example.org"),
		"text": "x"
	}))
	.await;
	assert_eq!(
		rcpt,
		vec![
			"ana@elsewhere.example",
			"bob@elsewhere.example",
			"carol@elsewhere.example"
		]
	);
	assert_eq!(
		line(&raw, "To"),
		"To: Ana Perez <ana@elsewhere.example>, bob@elsewhere.example"
	);
	assert_eq!(line(&raw, "Cc"), "Cc: Carol <carol@elsewhere.example>");
	assert_eq!(
		line(&raw, "Reply-To"),
		"Reply-To: Help Desk <help@example.org>"
	);
}

#[tokio::test]
async fn a_non_ascii_name_is_an_encoded_word_that_reads_back() {
	let name = "Ana Pérez Núñez 日本語";
	let (_, raw) = sent(json!({"to": [named(name, "ana@elsewhere.example")], "text": "x"})).await;
	assert!(
		header_block(&raw).is_ascii(),
		"the header block is pure ASCII"
	);
	assert!(
		line(&raw, "To").contains("=?UTF-8?B?"),
		"{}",
		line(&raw, "To")
	);
	assert_eq!(
		parsed(&raw, "To"),
		vec![(Some(name.to_string()), "ana@elsewhere.example".to_string())]
	);
}

#[tokio::test]
async fn a_long_non_ascii_name_stays_within_the_line_limit() {
	let name = "é".repeat(128);
	let (_, raw) = sent(json!({"to": [named(&name, "ana@elsewhere.example")], "text": "x"})).await;
	assert!(
		header_block(&raw).split("\r\n").all(|l| l.len() <= 100),
		"{}",
		header_block(&raw)
	);
	assert_eq!(parsed(&raw, "To")[0].0.as_deref(), Some(name.as_str()));
}

#[tokio::test]
async fn specials_are_quoted_and_read_back_unchanged() {
	for name in [
		"Doe, Jane",
		"Jane \"JJ\" Doe",
		r"Jane \ Doe",
		"Jane (Ops)",
		"Jane <team>",
		"jane@example.org",
		"Dr. Jane; Doe: Esq.",
	] {
		let (_, raw) = sent(json!({
			"to": [named(name, "jane@elsewhere.example")],
			"reply_to": named(name, "jane@example.org"),
			"text": "x"
		}))
		.await;
		for header in ["To", "Reply-To"] {
			let parsed = parsed(&raw, header);
			assert_eq!(parsed.len(), 1, "{name:?} in {header}");
			assert_eq!(parsed[0].0.as_deref(), Some(name), "{header}");
		}
		assert!(line(&raw, "To").contains(" \"") || line(&raw, "To").contains(": \""));
	}
}

#[tokio::test]
async fn a_name_that_cannot_be_written_safely_is_refused_with_its_field() {
	let cases = [
		(
			"to[1].name",
			json!({"to": ["a@elsewhere.example", named("Ana\r\nBcc: v@e.example", "b@elsewhere.example")]}),
		),
		(
			"to[0].name",
			json!({"to": [named("Ana\nx", "b@elsewhere.example")]}),
		),
		(
			"to[0].name",
			json!({"to": [named("Ana\u{0}", "b@elsewhere.example")]}),
		),
		(
			"to[0].name",
			json!({"to": [named(&"a".repeat(129), "b@elsewhere.example")]}),
		),
		(
			"cc[0].name",
			json!({"cc": [named("A\tB\r", "c@elsewhere.example")]}),
		),
		(
			"bcc[0].name",
			json!({"bcc": [named("A\r\nB", "c@elsewhere.example")]}),
		),
		(
			"reply_to.name",
			json!({"reply_to": named(&"é".repeat(129), "c@example.org")}),
		),
	];
	for (field, mut request) in cases {
		request["text"] = json!("x");
		let body = refused(request).await;
		let message = body["error"]["message"].as_str().expect("message");
		assert!(message.contains(field), "{field}: {message}");
	}
}

#[tokio::test]
async fn a_name_of_128_characters_is_accepted() {
	let name = "n".repeat(128);
	let (_, raw) = sent(json!({"to": [named(&name, "ana@elsewhere.example")], "text": "x"})).await;
	assert_eq!(parsed(&raw, "To")[0].0.as_deref(), Some(name.as_str()));
}

/// The raw answer to `body` posted to `/api/v1/send`, asking for `accept`.
async fn post_raw(dir: &std::path::Path, accept: &str, body: Value) -> (StatusCode, Vec<u8>) {
	use super::super::base::{TOKEN, test_state};
	let app = super::router(test_state(dir, 0));
	let request = axum::http::Request::builder()
		.method("POST")
		.uri("/api/v1/send")
		.header(
			axum::http::header::AUTHORIZATION,
			format!("Bearer {}", TOKEN.as_str()),
		)
		.header(axum::http::header::CONTENT_TYPE, "application/json")
		.header(axum::http::header::ACCEPT, accept)
		.body(axum::body::Body::from(body.to_string()))
		.expect("request");
	let response = tower::ServiceExt::oneshot(app, request)
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec())
}

#[tokio::test]
async fn the_problem_form_names_the_field() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, bytes) = post_raw(
		dir.path(),
		"application/problem+json",
		json!({"from": "alice@example.org", "text": "x",
			"to": ["a@elsewhere.example", "b@elsewhere.example", named("x\ny", "c@elsewhere.example")]}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	let problem: Value = serde_json::from_slice(&bytes).expect("json");
	assert_eq!(problem["errors"][0]["field"], "to[2].name", "{problem}");
}

#[tokio::test]
async fn the_name_and_address_string_form_stays_refused_and_points_to_the_object() {
	for request in [
		json!({"to": ["Ana Pérez <ana@elsewhere.example>"]}),
		json!({"cc": ["<ana@elsewhere.example>"]}),
		json!({"reply_to": "Ana <ana@example.org>"}),
	] {
		let mut request = request;
		request["to"] = request
			.get("to")
			.cloned()
			.unwrap_or(json!(["b@elsewhere.example"]));
		request["text"] = json!("x");
		let body = refused(request).await;
		let message = body["error"]["message"].as_str().expect("message");
		assert!(message.contains("\"name\""), "{message}");
	}
}

#[tokio::test]
async fn an_object_with_an_unknown_key_or_no_address_is_refused() {
	for to in [
		json!([{"name": "Ana", "address": "a@elsewhere.example", "extra": 1}]),
		json!([{"name": "Ana"}]),
		json!([{"address": 5}]),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (status, _) = post_raw(
			dir.path(),
			"application/json",
			json!({"from": "alice@example.org", "to": to, "text": "x"}),
		)
		.await;
		assert!(status.is_client_error(), "{status}");
		let spool = FsSpool::open(dir.path()).expect("spool");
		assert!(spool.list().expect("list").is_empty());
	}
}

#[tokio::test]
async fn bcc_names_appear_in_no_header_and_the_envelope_has_the_address_only() {
	let (rcpt, raw) = sent(json!({
		"bcc": [named("Secret Person", "hidden@elsewhere.example")],
		"text": "x"
	}))
	.await;
	assert!(rcpt.contains(&"hidden@elsewhere.example".to_string()));
	let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
	let head = text.split("\r\n\r\n").next().expect("head");
	assert!(!head.contains("secret"), "{head}");
	assert!(!head.contains("hidden@"), "{head}");
	assert!(!head.contains("bcc:"), "{head}");
}

#[tokio::test]
async fn one_address_with_two_names_is_one_recipient_and_the_first_name_wins() {
	let (rcpt, raw) = sent(json!({
		"to": [
			named("First Name", "ana@elsewhere.example"),
			named("Second Name", "ANA@elsewhere.example"),
		],
		"cc": [named("Other", "Ana@Elsewhere.Example")],
		"bcc": ["ana@elsewhere.example"],
		"text": "x"
	}))
	.await;
	assert_eq!(rcpt, vec!["ana@elsewhere.example"]);
	assert_eq!(line(&raw, "To"), "To: First Name <ana@elsewhere.example>");
	assert_eq!(line(&raw, "Cc"), "Cc: Other <ana@elsewhere.example>");
	assert!(!String::from_utf8_lossy(&raw).contains("Second"));
}

#[tokio::test]
async fn names_do_not_count_as_recipients_against_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let to: Vec<Value> = (0..5)
		.map(|i| named(&format!("Name {i}"), "same@elsewhere.example"))
		.collect();
	let (status, body) = send(dir.path(), json!({"to": to, "text": "x"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(queued(dir.path()).0, vec!["same@elsewhere.example"]);
}

#[tokio::test]
async fn the_signature_covers_the_header_that_carries_the_name() {
	use super::send_outbound::routed_state;
	let dir = tempfile::tempdir().expect("tempdir");
	let app = super::router(routed_state(dir.path()));
	let (status, body) = super::super::base::request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(super::super::base::TOKEN.as_str()),
		Some(json!({"from": "alice@example.org", "text": "x",
			"to": [named("Ana Pérez, Jr.", "ana@elsewhere.example")],
			"cc": [named("Carol", "carol@elsewhere.example")],
			"reply_to": named("Help", "help@example.org")})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	let signature = crate::dkim::test_support::signature_headers(&raw).join("");
	let unfolded = signature.replace("\r\n", "").replace([' ', '\t'], "");
	let signed = unfolded
		.split(';')
		.find_map(|tag| tag.strip_prefix("h="))
		.expect("h= tag")
		.to_ascii_lowercase();
	for header in ["to", "cc", "reply-to"] {
		assert!(
			signed.split(':').any(|h| h == header),
			"{header} in {signed}"
		);
	}
	assert!(line(&raw, "To").contains("=?UTF-8?B?"));
}
