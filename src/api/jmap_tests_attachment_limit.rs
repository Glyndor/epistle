//! The Session's `maxSizeAttachmentsPerEmail` is a size the server accepts:
//! an Email with attachments that large, and a short text body, is created.

use super::jmap_tests_email_create::{app, create, upload};
use super::tests::{TOKEN, request};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn an_attachment_of_the_advertised_size_is_accepted() {
	let (_dir, app) = app();
	let (status, session) = request(&app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let advertised =
		session["capabilities"]["urn:ietf:params:jmap:mail"]["maxSizeAttachmentsPerEmail"]
			.as_u64()
			.expect("maxSizeAttachmentsPerEmail");
	let size = usize::try_from(advertised).expect("fits");
	assert_eq!(
		size,
		crate::api::jmap::MAX_SIZE_ATTACHMENTS_PER_EMAIL,
		"the Session reports the limit the server enforces"
	);
	assert!(
		size < crate::smtp::session::MAX_MESSAGE_SIZE / 4 * 3,
		"base64 of the attachments must fit the message size"
	);
	let data: Vec<u8> = (0..=255u8).cycle().take(size).collect();
	let blob = upload(&app, "application/octet-stream", &data).await;
	let response = create(
		&app,
		json!({"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "attached"}},
			"attachments": [{"blobId": blob, "type": "application/octet-stream", "name": "a.bin"}]}),
	)
	.await;
	assert!(
		response["created"]["e"]["id"].is_string(),
		"an Email with {advertised} octets of attachments must be created: {}",
		response["notCreated"]
	);
}
