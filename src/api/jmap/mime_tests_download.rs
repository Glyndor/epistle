use crate::api::tests::{TOKEN, request_raw, request_with_body, test_state};
use crate::storage::MessageCrypto;
use axum::{
	Router,
	body::Body,
	http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn get_email(app: &Router, id: uuid::Uuid) -> Value {
	let (_, response) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(
			json!({"methodCalls":[["Email/get",{"accountId":"alice","ids":[id.to_string()]},"c"]]}),
		),
	)
	.await;
	response["methodResponses"][0][1]["list"][0].clone()
}

fn setup(raw: &[u8], crypto: MessageCrypto) -> (tempfile::TempDir, Router, uuid::Uuid) {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], raw, &crypto)
		.expect("append");
	let app = crate::api::router(test_state(dir.path(), 0).with_crypto(crypto));
	(dir, app, id)
}

async fn assert_download(app: &Router, part: &Value, expected: &[u8], media_type: &str) {
	let blob = part["blobId"].as_str().expect("leaf blob id");
	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.uri(format!("/jmap/download/alice/{blob}/part"))
				.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
				.body(Body::empty())
				.expect("request"),
		)
		.await
		.expect("response");
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"leaf blob must be downloadable through the existing route"
	);
	assert_eq!(
		response.headers()[header::CONTENT_TYPE],
		media_type,
		"part download must identify the leaf media type"
	);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	assert!(
		bytes.as_ref() == expected,
		"part download must return exactly the transfer-decoded octets"
	);
	assert_eq!(
		part["size"],
		json!(bytes.len()),
		"part size must equal downloaded octet count"
	);
}

#[tokio::test]
async fn mime_download_plain_text_leaf() {
	let (_dir, app, id) = setup(b"Subject: plain\r\n\r\nHello", MessageCrypto::disabled());
	let email = get_email(&app, id).await;
	assert_download(&app, &email["bodyStructure"], b"Hello", "text/plain").await;
}

#[tokio::test]
async fn mime_download_alternative_leaves() {
	let raw = b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8K\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>Hello</p>\r\n--b--\r\n";
	let (_dir, app, id) = setup(raw, MessageCrypto::disabled());
	let email = get_email(&app, id).await;
	let parts = &email["bodyStructure"]["subParts"];
	assert_download(&app, &parts[0], b"Hello\n", "text/plain").await;
	assert_download(&app, &parts[1], b"<p>Hello</p>", "text/html").await;
	let (status, _) = request_raw(
		&app,
		&format!("/jmap/download/alice/{id}.0/part"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"multipart containers must not be downloadable leaves"
	);
}

#[tokio::test]
async fn mime_download_base64_pdf_attachment() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nHello\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=doc.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n";
	let (_dir, app, id) = setup(raw, MessageCrypto::disabled());
	let email = get_email(&app, id).await;
	assert_download(
		&app,
		&email["attachments"][0],
		b"%PDF-1.4\n",
		"application/pdf",
	)
	.await;
}

#[tokio::test]
async fn mime_download_attached_message_preserves_rfc5322_octets() {
	use base64::Engine;
	let nested = b"Subject: nested\r\nContent-Type: multipart/mixed; boundary=n\r\n\r\n--n\r\n\r\nInside\r\n--n--\r\n";
	let encoded = base64::engine::general_purpose::STANDARD.encode(nested);
	let raw = format!(
		"Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}"
	);
	let (_dir, app, id) = setup(raw.as_bytes(), MessageCrypto::disabled());
	let email = get_email(&app, id).await;
	assert_download(&app, &email["bodyStructure"], nested, "message/rfc822").await;
	assert_eq!(
		email["bodyStructure"].get("subParts"),
		None,
		"attached message structure must remain a leaf"
	);
}

#[tokio::test]
async fn mime_download_charset_keeps_original_decoded_octets() {
	let raw = b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9\r\nnext";
	let (_dir, app, id) = setup(raw, MessageCrypto::disabled());
	let email = get_email(&app, id).await;
	assert_download(
		&app,
		&email["bodyStructure"],
		b"caf\xe9\r\nnext",
		"text/plain",
	)
	.await;
}

#[tokio::test]
async fn mime_download_encrypted_parts_require_message_ownership() {
	let crypto = MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");
	let raw = b"Subject: own\r\n\r\nOwned";
	let (dir, app, id) = setup(raw, crypto.clone());
	let email = get_email(&app, id).await;
	assert_download(&app, &email["bodyStructure"], b"Owned", "text/plain").await;
	let foreign = crate::imap::mailbox::append(dir.path(), "bob", "INBOX", &[], raw, &crypto)
		.expect("foreign message");
	for blob in [
		format!("{foreign}.0"),
		format!("{id}.999"),
		format!("{id}.00"),
		format!("{id}.0.1"),
	] {
		let (status, response) = request_raw(
			&app,
			&format!("/jmap/download/alice/{blob}/part"),
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(
			status,
			StatusCode::NOT_FOUND,
			"foreign and invalid part ids must be rejected"
		);
		let error: Value = serde_json::from_slice(&response).expect("error response");
		assert_eq!(
			error["type"], "urn:ietf:params:jmap:error:notFound",
			"invalid part download must report notFound"
		);
	}
	let (status, bytes) = request_raw(
		&app,
		&format!("/jmap/download/alice/{id}/message"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"whole-message downloads must remain available"
	);
	assert!(
		bytes == raw,
		"whole-message downloads must preserve all RFC 5322 octets"
	);
}
