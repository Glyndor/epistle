//! `Email/set` create and `Email/copy` store mail the way IMAP APPEND does, so
//! they stop at the account's storage quota: a blob uploaded once and turned into
//! many messages cannot grow the mailbox past it.

use super::base::{TOKEN, request_with_body, test_state};
use super::jmap_email_create::{create, upload};
use super::router;
use axum::http::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn email_set_create_stops_at_the_quota_of_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0).with_quota(40_000));
	let blob = upload(&app, "application/octet-stream", &vec![7u8; 12_000]).await;
	let spec = json!({"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "x"}},
		"attachments": [{"blobId": blob, "type": "application/octet-stream", "name": "a.bin"}]});
	let mut created = 0;
	let mut refused = None;
	for _ in 0..8 {
		let response = create(&app, spec.clone()).await;
		if response["created"]["e"]["id"].is_string() {
			created += 1;
		} else {
			refused = Some(response["notCreated"]["e"]["type"].clone());
			break;
		}
	}
	assert!(created >= 1, "the first message fits the quota");
	assert_eq!(refused, Some(json!("overQuota")), "created {created}");
}

#[tokio::test]
async fn email_copy_stops_at_the_quota_of_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0).with_quota(40_000));
	let blob = upload(&app, "application/octet-stream", &vec![7u8; 12_000]).await;
	let first = create(
		&app,
		json!({"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "x"}},
			"attachments": [{"blobId": blob, "type": "application/octet-stream", "name": "a.bin"}]}),
	)
	.await;
	let id = first["created"]["e"]["id"]
		.as_str()
		.expect("first id")
		.to_string();
	let mut refused = None;
	for _ in 0..8 {
		let call = json!(["Email/copy", {
			"fromAccountId": "alice", "accountId": "alice",
			"create": {"c": {"id": id, "mailboxIds": {"INBOX": true}}}
		}, "c1"]);
		let req = json!({"using": ["urn:ietf:params:jmap:mail"], "methodCalls": [call]});
		let (status, body) =
			request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let answer: Value = body["methodResponses"][0][1].clone();
		if !answer["created"]["c"]["id"].is_string() {
			refused = Some(answer["notCreated"]["c"]["type"].clone());
			break;
		}
	}
	assert_eq!(refused, Some(json!("overQuota")));
}
