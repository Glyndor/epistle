//! The REST account endpoints carry the display name: set on create,
//! changed or cleared with `PUT /api/v1/accounts/{name}/display_name`,
//! listed as given, refused with a line break.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

fn listed(body: &serde_json::Value, name: &str) -> serde_json::Value {
	body["accounts"]
		.as_array()
		.expect("accounts")
		.iter()
		.find(|account| account["name"] == name)
		.expect("listed")["display_name"]
		.clone()
}

async fn put(app: &Router, value: &str) -> (StatusCode, serde_json::Value) {
	let body = serde_json::json!({ "display_name": value });
	request_with_body(
		app,
		"PUT",
		"/api/v1/accounts/bob/display_name",
		Some(TOKEN.as_str()),
		Some(body),
	)
	.await
}

#[tokio::test]
async fn create_set_list_and_clear_a_display_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let create = serde_json::json!({
		"name": "bob",
		"addresses": ["bob@example.org"],
		"password": "Correct-Horse-Battery-9",
		"display_name": "Bob MÜLLER",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(create),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(listed(&body, "bob"), "Bob MÜLLER");
	assert_eq!(listed(&body, "alice"), serde_json::Value::Null);

	let (status, body) = put(&app, " Robert Müller ").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["display_name"], "Robert Müller");
	let (_, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(listed(&body, "bob"), "Robert Müller");

	let (status, body) = put(&app, "").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["display_name"], serde_json::Value::Null);

	let (status, body) = put(&app, "Bob\r\nBcc: x@example.net").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		body["error"]["message"],
		"the display name must not contain control characters or line breaks"
	);
}

async fn create_bob(app: &Router, display_name: &str) {
	let create = serde_json::json!({
		"name": "bob",
		"addresses": ["bob@example.org"],
		"password": "Correct-Horse-Battery-9",
		"display_name": display_name,
	});
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(create),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

async fn identity_name(app: &Router, account: &str) -> serde_json::Value {
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["Identity/get", {"accountId": account}, "c1"]],
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1]["list"][0]["name"].clone()
}

#[tokio::test]
async fn jmap_identity_name_is_the_display_name_or_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	create_bob(&app, "Bob MÜLLER").await;
	assert_eq!(identity_name(&app, "bob").await, "Bob MÜLLER");
	assert_eq!(
		identity_name(&app, "alice").await,
		"",
		"no display name: empty, never the account identifier"
	);
}

/// Send one message and return its `From:` header line.
async fn sent_from(dir: &std::path::Path, app: &Router, request: serde_json::Value) -> String {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let id = body["queued"]
		.as_str()
		.expect("queued")
		.parse()
		.expect("uuid");
	let spool = crate::storage::FsSpool::open(dir).expect("spool");
	let data = String::from_utf8(spool.load(id).expect("load").data).expect("utf8");
	data.lines()
		.find(|line| line.starts_with("From: "))
		.expect("From header")
		.to_string()
}

#[tokio::test]
async fn send_uses_the_display_name_in_from_unless_the_request_gives_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	create_bob(&app, "Bob MÜLLER").await;
	let send = |from: &str, from_name: Option<&str>| {
		let mut request = serde_json::json!({
			"from": from, "to": ["x@elsewhere.example"], "subject": "s", "text": "t",
		});
		if let Some(name) = from_name {
			request["from_name"] = serde_json::json!(name);
		}
		request
	};
	assert_eq!(
		sent_from(dir.path(), &app, send("bob@example.org", None)).await,
		"From: =?UTF-8?B?Qm9iIE3DnExMRVI=?= <bob@example.org>"
	);
	assert_eq!(
		sent_from(
			dir.path(),
			&app,
			send("bob@example.org", Some("Ops \"Desk\""))
		)
		.await,
		"From: \"Ops \\\"Desk\\\"\" <bob@example.org>"
	);
	assert_eq!(
		sent_from(dir.path(), &app, send("alice@example.org", None)).await,
		"From: alice@example.org"
	);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(send("bob@example.org", Some("Ops\r\nBcc: y@example.net"))),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
