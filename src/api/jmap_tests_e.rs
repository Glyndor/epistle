//! JMAP blob upload/download tests (RFC 8620 §6).

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// POST a raw body, optionally setting a request `Content-Type`, and parse the
/// JSON response — exercises JMAP blob upload's media-type handling.
async fn post_raw_ct(
	app: &Router,
	path: &str,
	token: Option<&str>,
	content_type: Option<&str>,
	body: &[u8],
) -> (StatusCode, serde_json::Value) {
	let mut builder = Request::builder().method("POST").uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	if let Some(content_type) = content_type {
		builder = builder.header(header::CONTENT_TYPE, content_type);
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::from(body.to_vec())).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	// Error responses may be plain text, so fall back to Null when not JSON.
	let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(status, json)
}

/// GET raw bytes plus the response `Content-Type` — asserts JMAP download
/// serves the media type recorded at upload time.
async fn request_raw_ct(
	app: &Router,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
	let mut builder = Request::builder().method("GET").uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let content_type = response
		.headers()
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.map(str::to_string);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, content_type, bytes.to_vec())
}

#[tokio::test]
async fn jmap_download_returns_raw_message() {
	use super::tests::request_raw;
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let raw = b"From: a@example.org\r\nSubject: dl\r\n\r\nbody\r\n";
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request_raw(
		&app,
		&format!("/jmap/download/alice/{id}/msg.eml"),
		Some(TOKEN),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, raw);

	// Unknown blob and unknown account both 404.
	let (status, _) = request_raw(
		&app,
		&format!("/jmap/download/alice/{}/x", uuid::Uuid::now_v7()),
		Some(TOKEN),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request_raw(&app, &format!("/jmap/download/ghost/{id}/x"), Some(TOKEN)).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	// Without a token the route is unauthorized.
	let (status, _) = request_raw(&app, &format!("/jmap/download/alice/{id}/x"), None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jmap_download_decrypts_encrypted_message() {
	// Encryption ON: the message is stored as ciphertext, but find_email_raw via
	// the download route must return the plaintext.
	use super::tests::request_raw;
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = crate::storage::MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");
	let raw = b"From: a@example.org\r\nSubject: dl\r\n\r\nencrypted body\r\n";
	let id = crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], raw, &crypto)
		.expect("append");
	// On disk it is ciphertext, not the plaintext.
	let stored = std::fs::read(dir.path().join(format!("accounts/alice/new/{id}.eml")))
		.expect("read stored");
	assert!(
		stored.starts_with(b"EPENC1\0"),
		"stored message is encrypted"
	);

	let app = router(test_state(dir.path(), 0).with_crypto(crypto));
	let (status, body) = request_raw(
		&app,
		&format!("/jmap/download/alice/{id}/msg.eml"),
		Some(TOKEN),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, raw, "download must return decrypted plaintext");
}

#[tokio::test]
async fn jmap_email_get_returns_decrypted_body() {
	// Email/get over an encrypted store must surface the plaintext body.
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = crate::storage::MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");
	let raw = b"From: a@example.org\r\nSubject: hi\r\n\r\nplaintext via jmap\r\n";
	let id = crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], raw, &crypto)
		.expect("append");
	let app = router(test_state(dir.path(), 0).with_crypto(crypto));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/get",
			{ "accountId": "alice", "ids": [id.to_string()],
			  "properties": ["preview"] }, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let preview = body["methodResponses"][0][1]["list"][0]["preview"]
		.as_str()
		.unwrap_or_default();
	assert!(preview.contains("plaintext via jmap"), "{body}");
}

#[tokio::test]
async fn jmap_upload_then_download_round_trips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let payload = b"hello blob \x00\x01\x02";

	// Upload echoes the request Content-Type and returns 200 (RFC 8620 §6.1).
	let (status, body) = post_raw_ct(
		&app,
		"/jmap/upload/alice",
		Some(TOKEN),
		Some("image/png"),
		payload,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["accountId"], "alice");
	assert_eq!(body["type"], "image/png");
	assert_eq!(body["size"], payload.len());
	let blob_id = body["blobId"].as_str().expect("blobId").to_string();

	// The uploaded blob downloads byte-for-byte with its recorded media type.
	let (status, content_type, got) = request_raw_ct(
		&app,
		&format!("/jmap/download/alice/{blob_id}/x"),
		Some(TOKEN),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(content_type.as_deref(), Some("image/png"));
	assert_eq!(got, payload);

	// Missing Content-Type falls back to octet-stream.
	let (_, body) = post_raw_ct(&app, "/jmap/upload/alice", Some(TOKEN), None, payload).await;
	assert_eq!(body["type"], "application/octet-stream");

	// Unknown account and missing token are rejected; the former with a JMAP
	// problem-details body.
	let (status, body) = post_raw_ct(&app, "/jmap/upload/ghost", Some(TOKEN), None, payload).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:notFound");
	let (status, _) = post_raw_ct(&app, "/jmap/upload/alice", None, None, payload).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jmap_upload_over_max_size_is_rejected() {
	use super::jmap::MAX_UPLOAD_SIZE;
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let payload = vec![0u8; MAX_UPLOAD_SIZE + 1];

	let (status, body) = post_raw_ct(&app, "/jmap/upload/alice", Some(TOKEN), None, &payload).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit");
	assert_eq!(body["limit"], "maxSizeUpload");
}

#[tokio::test]
async fn jmap_upload_within_quota_succeeds_over_quota_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A tiny per-account quota makes the over-quota path testable.
	let app = router(test_state(dir.path(), 0).with_quota(64));

	// A blob within the quota is stored and returns 200.
	let (status, body) =
		post_raw_ct(&app, "/jmap/upload/alice", Some(TOKEN), None, &[0u8; 32]).await;
	assert_eq!(status, StatusCode::OK, "{body}");

	// A second blob would push usage (32 already stored) past the 64-byte quota
	// and is refused with the JMAP storage limit error, fail-closed.
	let (status, body) =
		post_raw_ct(&app, "/jmap/upload/alice", Some(TOKEN), None, &[0u8; 64]).await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit");
	assert_eq!(body["limit"], "storage");
}
