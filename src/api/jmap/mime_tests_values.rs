use super::mime_tests_structure::ID;
use crate::api::tests::{TOKEN, request_with_body, test_state};
use serde_json::{Value, json};

const ALTERNATIVE: &[u8] = b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8K\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p>\r\n--b--\r\n";

async fn values(raw: &[u8], mut args: Value) -> Value {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(inbox.join(format!("{ID}.eml")), raw).expect("message");
	args["accountId"] = json!("alice");
	args["ids"] = json!([ID]);
	let app = crate::api::router(test_state(dir.path(), 0));
	let (_, result) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(json!({"methodCalls":[["Email/get",args,"c"]]})),
	)
	.await;
	result["methodResponses"][0][1]["list"][0]["bodyValues"].clone()
}

fn value(text: &str, truncated: bool, encoding_problem: bool) -> Value {
	json!({"value":text,"isEncodingProblem":encoding_problem,"isTruncated":truncated})
}

#[tokio::test]
async fn mime_values_default_fetches_no_parts() {
	assert_eq!(
		values(b"Subject: plain\r\n\r\nHello", json!({})).await,
		json!({}),
		"bodyValues must be empty without fetch flags"
	);
}

#[tokio::test]
async fn mime_values_text_flag_fetches_real_plain_part() {
	assert_eq!(
		values(ALTERNATIVE, json!({"fetchTextBodyValues":true})).await,
		json!({"1":value("Hello\n",false,false)}),
		"text fetch must return the transfer-decoded plain part under its real id"
	);
}

#[tokio::test]
async fn mime_values_html_flag_fetches_real_html_part() {
	assert_eq!(
		values(ALTERNATIVE, json!({"fetchHTMLBodyValues":true})).await,
		json!({"2":value("<p>Hello</p>",false,false)}),
		"HTML fetch must return only the selected HTML part"
	);
}

#[tokio::test]
async fn mime_values_all_fetches_text_attachments_without_nested_message_bodies() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nHello\r\n--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=note.txt\r\n\r\nNote\r\n--b\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nSubject: nested\r\n\r\nInside\r\n--b--\r\n";
	assert_eq!(
		values(
			raw,
			json!({"fetchAllBodyValues":true,"bodyProperties":["size"]})
		)
		.await,
		json!({"1":value("Hello",false,false),"2":value("Note",false,false)}),
		"all fetch must include text attachments and exclude binary and nested message content"
	);
}

#[tokio::test]
async fn mime_values_charset_and_line_endings_are_decoded() {
	let raw = b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9\r\nnext";
	assert_eq!(
		values(raw, json!({"fetchAllBodyValues":true})).await,
		json!({"0":value("café\nnext",false,false)}),
		"bodyValues must decode the charset and normalize CRLF to LF"
	);
}

#[tokio::test]
async fn mime_values_byte_limit_preserves_utf8_boundaries() {
	let raw = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9";
	assert_eq!(
		values(
			raw,
			json!({"fetchAllBodyValues":true,"maxBodyValueBytes":4})
		)
		.await,
		json!({"0":value("caf",true,false)}),
		"body value byte limits must truncate before a multibyte character"
	);
	assert_eq!(
		values(
			raw,
			json!({"fetchAllBodyValues":true,"maxBodyValueBytes":0})
		)
		.await,
		json!({"0":value("café",false,false)}),
		"zero byte limit must return the complete value"
	);
}

#[tokio::test]
async fn mime_values_html_limit_avoids_partial_tags() {
	assert_eq!(
		values(
			b"Content-Type: text/html\r\n\r\n<p>Hello</p>",
			json!({"fetchHTMLBodyValues":true,"maxBodyValueBytes":2})
		)
		.await,
		json!({"0":value("",true,false)}),
		"HTML byte limits must avoid returning a partial tag"
	);
}

#[tokio::test]
async fn mime_values_unknown_charset_is_reported() {
	assert_eq!(
		values(
			b"Content-Type: text/plain; charset=unknown\r\n\r\nHello",
			json!({"fetchAllBodyValues":true})
		)
		.await,
		json!({"0":value("Hello",false,true)}),
		"unknown charset must retain text and report an encoding problem"
	);
}

#[tokio::test]
async fn mime_values_unknown_transfer_encoding_is_reported() {
	assert_eq!(
		values(
			b"Content-Type: text/plain\r\nContent-Transfer-Encoding: unknown\r\n\r\nHello",
			json!({"fetchAllBodyValues":true})
		)
		.await,
		json!({"0":value("Hello",false,true)}),
		"unknown transfer encoding must retain text and report an encoding problem"
	);
}

#[tokio::test]
async fn mime_values_malformed_encoding_is_reported() {
	assert_eq!(
		values(
			b"Content-Type: text/plain; charset=utf-8\r\n\r\nA\xffB",
			json!({"fetchAllBodyValues":true})
		)
		.await,
		json!({"0":value("A�B",false,true)}),
		"malformed UTF-8 must use replacement characters and report an encoding problem"
	);
}
