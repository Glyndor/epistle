use serde_json::{Value, json};

pub(super) const ID: &str = "00000000-0000-4000-8000-000000000001";

pub(super) fn email(raw: &[u8]) -> Value {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(inbox.join(format!("{ID}.eml")), raw).expect("message");
	super::find_email(
		dir.path(),
		"alice",
		ID,
		&crate::storage::MessageCrypto::disabled(),
		&Value::Null,
	)
	.expect("email")
}

pub(super) fn leaf(part_id: &str, size: usize, media_type: &str, charset: Value) -> Value {
	json!({"partId":part_id,"blobId":format!("{ID}.{part_id}"),"size":size,
		"name":null,"type":media_type,"charset":charset,"disposition":null,
		"cid":null,"language":null,"location":null})
}

#[test]
fn mime_structure_plain_text_has_complete_leaf() {
	assert_eq!(
		email(b"Subject: plain\r\n\r\nHello")["bodyStructure"],
		leaf("0", 5, "text/plain", json!("us-ascii")),
		"plain text must expose a complete MIME leaf"
	);
}

#[test]
fn mime_structure_alternative_has_real_children() {
	let raw = b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p>\r\n--b--\r\n";
	assert_eq!(
		email(raw)["bodyStructure"],
		json!({"partId":null,"blobId":null,
		"size":0,"name":null,"type":"multipart/alternative","charset":null,
		"disposition":null,"cid":null,"language":null,"location":null,
		"subParts":[leaf("1",5,"text/plain",json!("utf-8")),leaf("2",12,"text/html",json!("utf-8"))]}),
		"alternative must expose its two MIME children"
	);
}

#[test]
fn mime_structure_mixed_decodes_attachment_metadata_and_size() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nHello\r\n--b\r\nContent-Type: application/pdf; name=old.pdf\r\nContent-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <doc>\r\nContent-Language: en, es\r\nContent-Location: https://example.org/doc\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n";
	let mut pdf = leaf("2", 9, "application/pdf", Value::Null);
	pdf["name"] = json!("résumé.pdf");
	pdf["disposition"] = json!("attachment");
	pdf["cid"] = json!("doc");
	pdf["language"] = json!(["en", "es"]);
	pdf["location"] = json!("https://example.org/doc");
	assert_eq!(
		email(raw)["bodyStructure"]["subParts"],
		json!([leaf("1", 5, "text/plain", json!("us-ascii")), pdf]),
		"mixed must expose decoded attachment metadata and octet size"
	);
}

#[test]
fn mime_structure_attached_message_is_a_leaf() {
	let nested = "Subject: nested\r\n\r\nInside";
	let raw = format!("Content-Type: message/rfc822\r\n\r\n{nested}");
	assert_eq!(
		email(raw.as_bytes())["bodyStructure"],
		leaf("0", nested.len(), "message/rfc822", Value::Null),
		"attached messages must remain downloadable leaves"
	);
}

#[test]
fn mime_structure_charset_size_counts_original_octets() {
	assert_eq!(
		email(b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9")["bodyStructure"],
		leaf("0", 4, "text/plain", json!("iso-8859-1")),
		"leaf size must count transfer-decoded octets before charset conversion"
	);
}

#[tokio::test]
async fn mime_structure_headers_are_returned_only_when_requested() {
	use crate::api::tests::{TOKEN, request_with_body, test_state};
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(
		inbox.join(format!("{ID}.eml")),
		b"Content-Type: text/plain; charset=utf-8\r\nX-Note: one\r\n\ttwo\r\n\r\nHello",
	)
	.expect("message");
	let app = crate::api::router(test_state(dir.path(), 0));
	let (_, response) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(
			json!({"methodCalls":[["Email/get",{"accountId":"alice","ids":[ID],
		"bodyProperties":["partId","headers"]},"c"]]}),
		),
	)
	.await;
	assert_eq!(
		response["methodResponses"][0][1]["list"][0]["bodyStructure"],
		json!({"partId":"0","headers":[
			{"name":"Content-Type","value":" text/plain; charset=utf-8"},
			{"name":"X-Note","value":" one\r\n\ttwo"}]}),
		"bodyProperties must select raw part headers"
	);
}
