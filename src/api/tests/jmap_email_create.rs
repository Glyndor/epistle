//! JMAP `Email/set` create builds the whole message (RFC 8621 section 4.6):
//! text and HTML bodies from `bodyValues`, attachments from uploaded blobs,
//! or an explicit `bodyStructure`; what it stores reads back the same
//! through `Email/get`, and bad combinations are refused.

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn jmap(app: &Router, call: Value) -> Value {
	let req = json!({"using": ["urn:ietf:params:jmap:mail"], "methodCalls": [call]});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

/// Create one Email from `spec` (merged into a minimal draft); the
/// `Email/set` response.
pub(in super::super) async fn create(app: &Router, spec: Value) -> Value {
	let mut email = json!({
		"mailboxIds": {"INBOX": true},
		"from": [{"email": "alice@example.org"}],
		"to": [{"email": "bob@elsewhere.example"}],
		"subject": "Built",
	});
	if let (Some(base), Some(extra)) = (email.as_object_mut(), spec.as_object()) {
		base.extend(extra.clone());
	}
	jmap(
		app,
		json!(["Email/set", {"accountId": "alice", "create": {"e": email}}, "c1"]),
	)
	.await
}

/// The stored Email, with its body parts and every body value.
async fn read_back(app: &Router, response: &Value) -> Value {
	let id = response["created"]["e"]["id"]
		.as_str()
		.unwrap_or_else(|| panic!("created: {response}"));
	let get = jmap(
		app,
		json!(["Email/get", {"accountId": "alice", "ids": [id], "fetchAllBodyValues": true,
			"properties": ["bodyStructure", "textBody", "htmlBody", "attachments", "bodyValues"]},
			"c2"]),
	)
	.await;
	get["list"][0].clone()
}

/// The value of the body part listed first under `list` (`textBody`,
/// `htmlBody`) and its type.
fn body_of(email: &Value, list: &str) -> (String, String) {
	let part = &email[list][0];
	let part_id = part["partId"].as_str().expect("partId");
	(
		part["type"].as_str().expect("type").to_string(),
		email["bodyValues"][part_id]["value"]
			.as_str()
			.expect("value")
			.to_string(),
	)
}

pub(in super::super) async fn upload(app: &Router, content_type: &str, data: &[u8]) -> String {
	let request = Request::builder()
		.method("POST")
		.uri("/jmap/upload/alice")
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.header(header::CONTENT_TYPE, content_type)
		.body(Body::from(data.to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let body: Value = serde_json::from_slice(&bytes).expect("json");
	body["blobId"].as_str().expect("blobId").to_string()
}

async fn download(app: &Router, blob_id: &str) -> Vec<u8> {
	let request = Request::builder()
		.uri(format!("/jmap/download/alice/{blob_id}/x"))
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.body(Body::empty())
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	assert_eq!(response.status(), StatusCode::OK);
	axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body")
		.to_vec()
}

pub(in super::super) fn app() -> (tempfile::TempDir, Router) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	(dir, app)
}

#[tokio::test]
async fn html_body_only_is_stored_as_text_html() {
	let (_dir, app) = app();
	let created = create(
		&app,
		json!({"htmlBody": [{"partId": "h", "type": "text/html"}],
			"bodyValues": {"h": {"value": "<p>Grüße</p>"}}}),
	)
	.await;
	let email = read_back(&app, &created).await;
	assert_eq!(
		body_of(&email, "htmlBody"),
		("text/html".to_string(), "<p>Grüße</p>".to_string())
	);
}

#[tokio::test]
async fn text_and_html_bodies_are_an_alternative() {
	let (_dir, app) = app();
	let created = create(
		&app,
		json!({"textBody": [{"partId": "t", "type": "text/plain"}],
			"htmlBody": [{"partId": "h", "type": "text/html"}],
			"bodyValues": {"t": {"value": "plain"}, "h": {"value": "<b>rich</b>"}}}),
	)
	.await;
	let email = read_back(&app, &created).await;
	assert_eq!(email["bodyStructure"]["type"], "multipart/alternative");
	assert_eq!(
		body_of(&email, "textBody"),
		("text/plain".into(), "plain".into())
	);
	assert_eq!(
		body_of(&email, "htmlBody"),
		("text/html".into(), "<b>rich</b>".into())
	);
}

#[tokio::test]
async fn an_uploaded_blob_attachment_round_trips() {
	let (_dir, app) = app();
	let data: Vec<u8> = (0..=255u8).cycle().take(4000).collect();
	let blob = upload(&app, "application/pdf", &data).await;
	let created = create(
		&app,
		json!({"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "see attached"}},
			"attachments": [{"blobId": blob, "type": "application/pdf", "name": "Bericht März.pdf"}]}),
	)
	.await;
	let email = read_back(&app, &created).await;
	assert_eq!(email["bodyStructure"]["type"], "multipart/mixed");
	assert_eq!(body_of(&email, "textBody").1, "see attached");
	let attachment = &email["attachments"][0];
	assert_eq!(attachment["type"], "application/pdf");
	assert_eq!(attachment["name"], "Bericht März.pdf");
	let stored = attachment["blobId"].as_str().expect("attachment blobId");
	assert_eq!(download(&app, stored).await, data, "the attachment bytes");
}

#[tokio::test]
async fn an_explicit_body_structure_is_written_as_given() {
	let (_dir, app) = app();
	let blob = upload(&app, "image/png", b"\x89PNG\r\n\x1a\nxyz").await;
	let created = create(
		&app,
		json!({"bodyStructure": {"type": "multipart/related", "subParts": [
				{"partId": "h", "type": "text/html"},
				{"blobId": blob, "type": "image/png", "cid": "logo@x", "disposition": "inline"},
			]},
			"bodyValues": {"h": {"value": "<img src=\"cid:logo@x\">"}}}),
	)
	.await;
	let email = read_back(&app, &created).await;
	let structure = &email["bodyStructure"];
	assert_eq!(structure["type"], "multipart/related");
	assert_eq!(structure["subParts"][0]["type"], "text/html");
	assert_eq!(structure["subParts"][1]["type"], "image/png");
	assert_eq!(structure["subParts"][1]["cid"], "logo@x");
	assert_eq!(body_of(&email, "htmlBody").1, "<img src=\"cid:logo@x\">");
}

#[tokio::test]
async fn invalid_combinations_are_refused() {
	let (_dir, app) = app();
	let values = json!({"t": {"value": "x"}});
	let cases = [
		json!({"bodyStructure": {"partId": "t"}, "textBody": [{"partId": "t"}], "bodyValues": values}),
		json!({"textBody": [{"partId": "t"}, {"partId": "t"}], "bodyValues": values}),
		json!({"textBody": [{"partId": "t", "type": "text/html"}], "bodyValues": values}),
		json!({"textBody": [{"partId": "t", "blobId": "b"}], "bodyValues": values}),
		json!({"textBody": [{"partId": "t", "charset": "latin1"}], "bodyValues": values}),
		json!({"textBody": [{"partId": "missing"}], "bodyValues": values}),
		json!({"textBody": [{"partId": "t"}], "bodyValues": values,
			"header:Content-Type:asText": "text/html"}),
		json!({"textBody": [{"partId": "t"}], "bodyValues": values,
			"headers": [{"name": "Content-Transfer-Encoding", "value": "base64"}]}),
		json!({"textBody": [{"partId": "t", "headers": [
			{"name": "Content-Transfer-Encoding", "value": "8bit"}]}], "bodyValues": values}),
		json!({"bodyStructure": {"type": "multipart/mixed", "partId": "t", "subParts": []},
			"bodyValues": values}),
	];
	for spec in cases {
		let response = create(&app, spec.clone()).await;
		assert_eq!(
			response["notCreated"]["e"]["type"], "invalidProperties",
			"{spec} must be refused: {response}"
		);
	}
	let missing = uuid::Uuid::now_v7().to_string();
	let response = create(&app, json!({"attachments": [{"blobId": missing}]})).await;
	assert_eq!(
		response["notCreated"]["e"]["type"], "blobNotFound",
		"{response}"
	);
	assert_eq!(response["notCreated"]["e"]["notFound"], json!([missing]));
}
