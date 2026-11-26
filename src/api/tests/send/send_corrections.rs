//! Four corrections to `POST /api/v1/send`: `reply_to` takes a list, a
//! message with only Bcc recipients says so in `To`, a message with nothing in
//! it is refused, and a refusal for a limit names the limit.

use super::send_rich::{queued, send};
use crate::storage::FsSpool;
use axum::http::StatusCode;
use serde_json::{Value, json};

/// The unfolded header block of `raw`.
fn head(raw: &[u8]) -> String {
	let text = String::from_utf8_lossy(raw).replace("\r\n ", " ");
	text.split("\r\n\r\n")
		.next()
		.unwrap_or_default()
		.to_string()
}

/// Whether the header block holds a line that starts with `prefix`.
fn has_line(head: &str, prefix: &str) -> bool {
	head.lines().any(|line| line.starts_with(prefix))
}

/// The message of a request refused with `400`.
async fn refused(extra: Value) -> (Value, usize) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), extra).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let queued = FsSpool::open(dir.path())
		.expect("spool")
		.list()
		.expect("list");
	(body, queued.len())
}

fn named(name: &str, address: &str) -> Value {
	json!({"name": name, "address": address})
}

#[tokio::test]
async fn reply_to_takes_a_list_and_writes_one_header() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"text": "x", "reply_to": [
			"Support@Example.org",
			named("Help Desk", "help@example.org"),
			"support@example.org",
		]}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	let head = head(&raw);
	assert!(
		head.contains("\r\nReply-To: support@example.org, Help Desk <help@example.org>\r\n")
			|| head.contains("\nReply-To: support@example.org, Help Desk <help@example.org>"),
		"{head}"
	);
	assert_eq!(head.matches("Reply-To:").count(), 1, "{head}");
}

#[tokio::test]
async fn reply_to_keeps_the_single_form_and_an_empty_list_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, _) = send(
		dir.path(),
		json!({"text": "x", "reply_to": named("Help", "help@example.org")}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(head(&queued(dir.path()).1).contains("Reply-To: Help <help@example.org>"));
	let other = tempfile::tempdir().expect("tempdir");
	let (status, _) = send(other.path(), json!({"text": "x", "reply_to": []})).await;
	assert_eq!(status, StatusCode::OK);
	assert!(!has_line(&head(&queued(other.path()).1), "Reply-To:"));
}

#[tokio::test]
async fn a_bad_entry_in_the_reply_to_list_is_refused_and_named() {
	for (field, reply_to) in [
		(
			"reply_to[1].name",
			json!([
				"a@example.org",
				named("A\r\nBcc: x@elsewhere.example", "b@example.org")
			]),
		),
		("reply_to[0]", json!(["Ana <ana@example.org>"])),
		("reply_to", json!(["not an address"])),
		(
			"reply_to",
			json!(["a@example.org\r\nBcc: victim@elsewhere.example"]),
		),
	] {
		let (body, queued) = refused(json!({"text": "x", "reply_to": reply_to})).await;
		let message = body["error"]["message"].as_str().expect("message");
		assert!(
			message.contains(field) || field == "reply_to",
			"{field}: {message}"
		);
		assert_eq!(queued, 0, "nothing is queued for {reply_to}");
	}
}

#[tokio::test]
async fn reply_to_is_bounded() {
	let many: Vec<String> = (0..11).map(|i| format!("r{i}@example.org")).collect();
	let (body, queued) = refused(json!({"text": "x", "reply_to": many})).await;
	assert!(
		body["error"]["message"]
			.as_str()
			.is_some_and(|m| m.contains("maximum is 10")),
		"{body}"
	);
	assert_eq!(queued, 0);
	let ten: Vec<String> = (0..10).map(|i| format!("r{i}@example.org")).collect();
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"text": "x", "reply_to": ten})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn only_bcc_recipients_give_an_empty_group_in_to() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"text": "x", "to": [], "bcc": ["hidden@elsewhere.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (recipients, raw) = queued(dir.path());
	let head = head(&raw);
	assert!(has_line(&head, "To: undisclosed-recipients:;"), "{head}");
	assert!(
		!head.contains("hidden@"),
		"Bcc stays out of the headers: {head}"
	);
	assert_eq!(recipients, ["hidden@elsewhere.example"]);
}

#[tokio::test]
async fn the_empty_group_is_written_only_when_no_one_else_is_named() {
	for (extra, to_line) in [
		(
			json!({"to": ["a@elsewhere.example"], "bcc": ["b@elsewhere.example"]}),
			true,
		),
		(json!({"to": [], "cc": ["a@elsewhere.example"]}), false),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut request = json!({"text": "x"});
		request
			.as_object_mut()
			.expect("object")
			.extend(extra.as_object().expect("object").clone());
		let (status, body) = send(dir.path(), request).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let head = head(&queued(dir.path()).1);
		assert!(!head.contains("undisclosed-recipients"), "{head}");
		assert_eq!(
			has_line(&head, "To: a@elsewhere.example"),
			to_line,
			"{head}"
		);
	}
}

#[tokio::test]
async fn a_message_with_nothing_in_it_is_refused() {
	for extra in [
		json!({}),
		json!({"text": "", "html": "", "subject": ""}),
		json!({"attachments": [], "inline": []}),
	] {
		let (body, queued) = refused(extra.clone()).await;
		assert_eq!(body["error"]["code"], "invalid_input", "{extra}: {body}");
		assert!(
			body["error"]["message"]
				.as_str()
				.is_some_and(|m| m.contains("needs a subject")),
			"{extra}: {body}"
		);
		assert_eq!(queued, 0, "{extra}");
	}
}

#[tokio::test]
async fn any_one_part_makes_a_message() {
	for extra in [
		json!({"subject": "ping"}),
		json!({"text": "x"}),
		json!({"html": "<p>x</p>"}),
		json!({"attachments": [{"name": "a.txt", "content_type": "text/plain", "data": ""}]}),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (status, body) = send(dir.path(), extra.clone()).await;
		assert_eq!(status, StatusCode::OK, "{extra}: {body}");
	}
}

#[tokio::test]
async fn an_empty_message_does_not_hide_a_more_specific_refusal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"from": "mallory@elsewhere.example"})).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert_eq!(body["error"]["code"], "forbidden_from");
}

#[tokio::test]
async fn a_refusal_for_a_limit_names_the_limit() {
	let parts: Vec<Value> = (0..101)
		.map(|_| json!({"name": "a", "content_type": "text/plain", "data": ""}))
		.collect();
	let headers: serde_json::Map<String, Value> =
		(0..33).map(|i| (format!("X-H{i}"), json!("v"))).collect();
	let urls: Vec<String> = (0..5)
		.map(|i| format!("https://example.org/u/{i}"))
		.collect();
	let ids: Vec<String> = (0..101)
		.map(|i| format!("<a{i}@elsewhere.example>"))
		.collect();
	let recipients: Vec<String> = (0..101)
		.map(|i| format!("r{i}@elsewhere.example"))
		.collect();
	for (extra, limit) in [
		(json!({"text": "x", "to": recipients}), "100"),
		(json!({"text": "x", "attachments": parts}), "100"),
		(json!({"text": "x", "headers": headers}), "32"),
		(json!({"text": "x", "list_unsubscribe": urls}), "4"),
		(json!({"text": "x", "references": ids.join(" ")}), "100"),
		(
			json!({"text": "x", "in_reply_to": "<a@b.example> <c@d.example>"}),
			"1",
		),
	] {
		let (body, queued) = refused(extra).await;
		let message = body["error"]["message"].as_str().expect("message");
		assert!(message.contains(limit), "{limit}: {message}");
		assert_eq!(queued, 0);
	}
}

/// A client of 0.14.0 may write `null` for a field it leaves out: `reply_to`
/// was optional, and a field that release did not know was read as absent.
#[tokio::test]
async fn reply_to_null_is_the_same_as_omitted() {
	for extra in [
		json!({"text": "x", "reply_to": null}),
		json!({"text": "x", "dry_run": null}),
		json!({"text": "x"}),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (status, body) = send(dir.path(), extra.clone()).await;
		assert_eq!(status, StatusCode::OK, "{extra}: {body}");
		assert!(body.get("queued").is_some(), "{extra}: it was sent, {body}");
		assert!(
			!has_line(&head(&queued(dir.path()).1), "Reply-To:"),
			"{extra}"
		);
	}
}
