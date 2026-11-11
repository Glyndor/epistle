//! `EmailSubmission/set` under the send switch.

use axum::http::StatusCode;

use super::super::base::request_with_body;
use super::support::{OFF, ON, app, secret};

/// Store a message in `account`'s mailbox and submit it as itself; the method
/// response.
async fn submit(app: &axum::Router, dir: &std::path::Path, account: &str) -> serde_json::Value {
	let inbox = dir.join("accounts").join(account).join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let address = format!("{account}@example.org");
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!("From: {address}\r\nTo: dest@remote.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	)
	.expect("write");
	let request = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": account,
			"create": { "s1": {
				"emailId": id.to_string(),
				"envelope": {"mailFrom": {"email": address},
					"rcptTo": [{"email": "dest@remote.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(&secret(account)),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn a_submission_from_an_account_with_sending_off_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = submit(&app, dir.path(), OFF).await;
	assert!(response["created"]["s1"].is_null(), "{response}");
	assert_eq!(response["notCreated"]["s1"]["type"], "forbiddenToSend");
	assert_eq!(
		response["notCreated"]["s1"]["description"],
		"sending is turned off for this account"
	);
}

#[tokio::test]
async fn an_account_beside_it_still_submits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = submit(&app, dir.path(), ON).await;
	assert!(response["created"]["s1"]["id"].is_string(), "{response}");
}
