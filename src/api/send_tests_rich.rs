//! `POST /api/v1/send` builds a full MIME message: text and/or HTML,
//! attachments and inline parts, within the message size limit, with Bcc
//! recipients on the envelope only.

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use crate::storage::FsSpool;
use axum::http::StatusCode;
use base64::Engine;
use mail_parser::{MessageParser, MimeHeaders};
use serde_json::{Value, json};

/// Send `extra` merged into a minimal request; the status and the body.
pub(super) async fn send(dir: &std::path::Path, extra: Value) -> (StatusCode, Value) {
	let mut request = json!({"from": "alice@example.org", "to": ["bob@elsewhere.example"]});
	if let (Some(base), Some(extra)) = (request.as_object_mut(), extra.as_object()) {
		base.extend(extra.clone());
	}
	let app = router(test_state(dir, 0));
	request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(request),
	)
	.await
}

/// The one queued message: its envelope recipients and its bytes.
pub(super) fn queued(dir: &std::path::Path) -> (Vec<String>, Vec<u8>) {
	let spool = FsSpool::open(dir).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1, "exactly one queued message");
	let entry = spool.load(ids[0]).expect("load");
	(entry.envelope.recipients, entry.data)
}

/// Every part's `type/subtype`, depth first.
fn shape(raw: &[u8]) -> Vec<String> {
	let message = MessageParser::default().parse(raw).expect("parse");
	message
		.parts
		.iter()
		.map(|part| {
			let ct = part.content_type().expect("content type");
			format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or(""))
		})
		.collect()
}

#[tokio::test]
async fn text_only_is_one_text_plain_part() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"text": "hello"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	assert_eq!(shape(&raw), ["text/plain"]);
	let message = MessageParser::default().parse(&raw).expect("parse");
	assert_eq!(message.body_text(0).expect("text").as_ref(), "hello\r\n");
}

#[tokio::test]
async fn html_only_is_one_text_html_part() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"html": "<p>Grüße</p>"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	assert_eq!(shape(&raw), ["text/html"]);
	let message = MessageParser::default().parse(&raw).expect("parse");
	assert_eq!(
		message.body_html(0).expect("html").as_ref(),
		"<p>Grüße</p>\r\n"
	);
}

#[tokio::test]
async fn text_and_html_are_an_alternative_with_text_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({"text": "plain", "html": "<b>rich</b>"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	assert_eq!(
		shape(&raw),
		["multipart/alternative", "text/plain", "text/html"]
	);
}

#[tokio::test]
async fn attachments_and_inline_parts_round_trip_byte_for_byte() {
	let dir = tempfile::tempdir().expect("tempdir");
	let pdf: Vec<u8> = b"%PDF-1.7\n"
		.iter()
		.copied()
		.chain((0..=255u8).cycle().take(3000))
		.collect();
	let png = b"\x89PNG\r\n\x1a\n\x00\x01\x02".to_vec();
	let b64 = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);
	let name = "Überweisung für März.pdf";
	let (status, body) = send(
		dir.path(),
		json!({
			"text": "see attached",
			"html": "<img src=\"cid:logo@example.org\">",
			"attachments": [{"name": name, "content_type": "", "data": b64(&pdf)}],
			"inline": [{"name": "logo.png", "content_type": "image/png",
				"content_id": "logo@example.org", "data": b64(&png)}],
		}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	assert_eq!(
		shape(&raw),
		[
			"multipart/mixed",
			"multipart/alternative",
			"text/plain",
			"multipart/related",
			"text/html",
			"image/png",
			"application/pdf"
		],
		"the empty content type is detected from the bytes"
	);
	let message = MessageParser::default().parse(&raw).expect("parse");
	let inline = &message.parts[5];
	assert_eq!(inline.content_id(), Some("logo@example.org"));
	assert_eq!(inline.contents(), png.as_slice());
	let attachment = &message.parts[6];
	assert_eq!(attachment.attachment_name(), Some(name));
	assert_eq!(attachment.contents(), pdf.as_slice());
}

#[tokio::test]
async fn an_attachment_with_bad_base64_or_a_multipart_type_is_refused() {
	for attachment in [
		json!({"name": "a", "content_type": "text/plain", "data": "not base64!"}),
		json!({"name": "a", "content_type": "multipart/mixed", "data": "eA=="}),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (status, body) = send(dir.path(), json!({"attachments": [attachment]})).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
		assert_eq!(body["error"]["code"], "invalid_input");
	}
}

#[tokio::test]
async fn a_message_over_the_size_limit_once_built_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Every `=` takes three octets in quoted-printable: the request fits the
	// body limit, the built message does not fit the message size.
	let text = "=".repeat(crate::smtp::session::MAX_MESSAGE_SIZE / 3 + 1024);
	let (status, body) = send(dir.path(), json!({"text": text})).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
	assert_eq!(body["error"]["code"], "message_too_large");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "nothing queued");
}

/// The configured `[server] max_message_size` is the cap on the `POST
/// /api/v1/send` body too: the request body's `text` plus the headers
/// the endpoint writes itself grows past the cap, and the layer rejects
/// the body before any handler runs. axum's `DefaultBodyLimit` answers
/// a plain-text `413`, not a JSON envelope, so the assertion reads the
/// status alone and skips the body parse.
#[tokio::test]
async fn v1_send_body_over_the_configured_cap_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let small = 4 * 1024;
	let app = router(test_state(dir.path(), 0).with_max_message_size(small));
	let text = "x".repeat(small);
	let request = json!({
		"from": "alice@example.org",
		"to": ["bob@elsewhere.example"],
		"text": text,
	});
	// Inline the request so the body-limit 413 (a plain-text response,
	// not JSON) does not crash the assertion helper's `from_slice` call.
	use tower::ServiceExt;
	let axum_request = axum::http::Request::builder()
		.method("POST")
		.uri("/api/v1/send")
		.header(
			axum::http::header::AUTHORIZATION,
			format!("Bearer {}", TOKEN.as_str()),
		)
		.header(axum::http::header::CONTENT_TYPE, "application/json")
		.body(axum::body::Body::from(request.to_string()))
		.expect("request");
	let response = app.oneshot(axum_request).await.expect("response");
	let status = response.status();
	assert_eq!(
		status,
		StatusCode::PAYLOAD_TOO_LARGE,
		"a body whose built message exceeds [server] max_message_size must be refused",
	);
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(
		spool.list().expect("list").is_empty(),
		"nothing may be queued when the body cap is exceeded"
	);
}

#[tokio::test]
async fn bcc_is_on_the_envelope_and_nowhere_in_the_headers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"cc": ["carol@elsewhere.example"], "bcc": ["hidden@elsewhere.example"],
			"text": "x"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (recipients, raw) = queued(dir.path());
	assert_eq!(
		recipients,
		[
			"bob@elsewhere.example",
			"carol@elsewhere.example",
			"hidden@elsewhere.example"
		]
	);
	let text = String::from_utf8_lossy(&raw);
	assert!(
		text.contains("\r\nCc: carol@elsewhere.example\r\n"),
		"{text}"
	);
	assert!(
		!text.contains("hidden@"),
		"the Bcc address must not be in the message"
	);
	assert!(
		!text.to_ascii_lowercase().contains("\nbcc:"),
		"no Bcc header"
	);
}
