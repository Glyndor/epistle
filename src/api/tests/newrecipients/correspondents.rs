use super::*;
use serde_json::json;

#[tokio::test]
async fn rest_uncapped_submission_records_correspondents() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state_with_cap(dir.path(), None);
	let store = state.correspondents().expect("store").clone();
	let app = router(state);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "alice@example.org", "to": ["bob@example.net"], "subject": "hello", "text": "body"
		})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"uncapped REST submission must queue successfully"
	);
	assert!(
		store.knows("alice", "bob@example.net"),
		"uncapped REST submission must record its correspondent"
	);
	assert_eq!(
		store
			.enforce_new_recipient_cap("alice", &["bob@example.net"], Some(0))
			.expect("cap"),
		crate::storage::CapOutcome::Allowed { new: 0 },
		"enabling the cap must preserve known REST correspondents"
	);
}

#[tokio::test]
async fn jmap_uncapped_submission_records_correspondents() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: hello\r\n\r\nbody\r\n",
	)
	.expect("write");
	let state = test_state_with_cap(dir.path(), None);
	let store = state.correspondents().expect("store").clone();
	let app = router(state);
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(json!({
        "using": ["urn:ietf:params:jmap:submission"],
        "methodCalls": [["EmailSubmission/set", {
            "accountId": "alice", "create": {"s1": {
                "emailId": id.to_string(), "identityId": "alice@example.org",
                "envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": [{"email": "bob@example.net"}]}
            }}
        }, "c1"]]
    }))).await;
	assert_eq!(status, StatusCode::OK, "JMAP request must succeed");
	assert!(
		body["methodResponses"][0][1]["created"]["s1"]["id"].is_string(),
		"uncapped JMAP submission must queue successfully"
	);
	assert!(
		store.knows("alice", "bob@example.net"),
		"uncapped JMAP submission must record its correspondent"
	);
	assert_eq!(
		store
			.enforce_new_recipient_cap("alice", &["bob@example.net"], Some(0))
			.expect("cap"),
		crate::storage::CapOutcome::Allowed { new: 0 },
		"enabling the cap must preserve known JMAP correspondents"
	);
}
