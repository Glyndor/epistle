//! Header injection on `POST /api/v1/send`: a CR/LF (or another control
//! character) in any field that reaches a header is refused with 400
//! before the message is built, and nothing is queued. One test per field.

use super::send_rich::send;
use crate::storage::FsSpool;
use axum::http::StatusCode;
use serde_json::{Value, json};

const EVIL: &str = "x@elsewhere.example\r\nBcc: victim@elsewhere.example";

/// A base request with `field` set to `value` must be refused and leave
/// the spool empty.
async fn assert_refused(field: &str, value: Value) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({ field: value, "text": "x" })).await;
	assert_eq!(
		status,
		StatusCode::BAD_REQUEST,
		"{field} must be refused: {body}"
	);
	assert_eq!(body["error"]["code"], "invalid_input", "{field}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(
		spool.list().expect("list").is_empty(),
		"{field}: nothing queued"
	);
}

/// A one-part list whose part has `key` set to `value`.
fn part_with(key: &str, value: &str) -> Value {
	let mut part = json!({"name": "a.png", "content_type": "image/png", "data": "eA==",
		"content_id": "c@example.org"});
	part[key] = json!(value);
	json!([part])
}

macro_rules! refused {
	($($test:ident: $field:expr => $value:expr;)*) => {$(
		#[tokio::test]
		async fn $test() {
			assert_refused($field, $value).await;
		}
	)*};
}

refused! {
	crlf_in_from: "from" => json!(EVIL);
	crlf_in_from_name: "from_name" => json!("Alice\r\nBcc: victim@elsewhere.example");
	crlf_in_to: "to" => json!([EVIL]);
	crlf_in_cc: "cc" => json!([EVIL]);
	crlf_in_bcc: "bcc" => json!([EVIL]);
	crlf_in_reply_to: "reply_to" => json!(EVIL);
	crlf_in_sender: "sender" => json!(EVIL);
	crlf_in_subject: "subject" => json!(EVIL);
	crlf_in_in_reply_to: "in_reply_to" => json!("<a@b>\r\nBcc: victim@elsewhere.example");
	crlf_in_references: "references" => json!("<a@b>\r\nBcc: victim@elsewhere.example");
	crlf_in_list_unsubscribe: "list_unsubscribe" => json!(["https://e.example/\r\nBcc: v@e"]);
	crlf_in_feedback_id: "feedback_id" => json!("a:b\r\nBcc: victim@elsewhere.example");
	crlf_in_auto_submitted: "auto_submitted" => json!("no\r\nBcc: victim@elsewhere.example");
	crlf_in_importance: "importance" => json!("high\r\nBcc: victim@elsewhere.example");
	crlf_in_priority: "priority" => json!("high\r\nBcc: victim@elsewhere.example");
	crlf_in_custom_header_name: "headers" => json!({ "X-A\r\nBcc: v@e.example": "v" });
	crlf_in_custom_header_value: "headers" => json!({ "X-Note": EVIL });
	crlf_in_attachment_name: "attachments" => part_with("name", EVIL);
	crlf_in_attachment_content_type: "attachments" => part_with("content_type", "image/png\r\nX-A: 1");
	crlf_in_attachment_content_id: "attachments" => part_with("content_id", EVIL);
	crlf_in_inline_name: "inline" => part_with("name", EVIL);
	crlf_in_inline_content_id: "inline" => part_with("content_id", EVIL);
	nul_in_attachment_name: "attachments" => part_with("name", "a\u{0}.png");
	escape_in_subject: "subject" => json!("a\u{1b}[2J");
}
