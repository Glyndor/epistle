use axum::http::StatusCode;
use serde_json::json;

use super::super::base::request_with_body;
use super::support::{ANN, BOB, queued, rig, secret};

/// Store a message in `account`'s mailbox and submit it; the method response.
async fn submit(rig: &super::support::Rig, account: &str) -> serde_json::Value {
	let inbox = rig.dir.path().join("accounts").join(account).join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let address = format!("{account}@example.org");
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!("From: {address}\r\nTo: dest@remote.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	)
	.expect("write");
	call(
		rig,
		account,
		json!(["EmailSubmission/set", {
			"accountId": account,
			"create": { "s1": {
				"emailId": id.to_string(),
				"envelope": {"mailFrom": {"email": address},
					"rcptTo": [{"email": "dest@remote.example"}]},
			} },
		}, "c1"]),
	)
	.await
}

async fn call(
	rig: &super::support::Rig,
	token_account: &str,
	method_call: serde_json::Value,
) -> serde_json::Value {
	let request = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [method_call],
	});
	let (status, body) = request_with_body(
		&rig.app,
		"POST",
		"/jmap/api",
		Some(&secret(token_account)),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

async fn cancel(rig: &super::support::Rig, account: &str, id: &str) -> serde_json::Value {
	call(
		rig,
		account,
		json!(["EmailSubmission/set", {
			"accountId": account,
			"update": { id: { "undoStatus": "canceled" } },
		}, "c2"]),
	)
	.await
}

#[tokio::test]
async fn a_held_submission_is_pending_and_a_cancel_update_takes_it_back() {
	let rig = rig(60, &[]);
	let response = submit(&rig, ANN).await;
	let created = &response["created"]["s1"];
	assert_eq!(created["undoStatus"], "pending", "{response}");
	assert!(
		created["sendAt"]
			.as_str()
			.is_some_and(|at| at.ends_with('Z'))
	);
	let id = created["id"].as_str().expect("id").to_string();
	let answer = cancel(&rig, ANN, &id).await;
	assert!(answer["updated"][&id].is_null(), "{answer}");
	assert!(answer["notUpdated"].as_object().expect("map").is_empty());
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert!(queued(rig.dir.path()).is_empty());
}

#[tokio::test]
async fn once_handed_on_the_update_is_refused_as_cannot_unsend() {
	let rig = rig(60, &[]);
	let response = submit(&rig, ANN).await;
	let id = response["created"]["s1"]["id"]
		.as_str()
		.expect("id")
		.to_string();
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	let answer = cancel(&rig, ANN, &id).await;
	assert_eq!(
		answer["notUpdated"][&id]["type"], "cannotUnsend",
		"{answer}"
	);
	assert_eq!(queued(rig.dir.path()).len(), 1);
}

#[tokio::test]
async fn another_account_cannot_cancel_through_its_own_account_id() {
	let rig = rig(60, &[]);
	let response = submit(&rig, ANN).await;
	let id = response["created"]["s1"]["id"]
		.as_str()
		.expect("id")
		.to_string();
	let answer = cancel(&rig, BOB, &id).await;
	assert_eq!(answer["notUpdated"][&id]["type"], "notFound", "{answer}");
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(queued(rig.dir.path()).len(), 1);
}

#[tokio::test]
async fn only_cancelling_is_an_allowed_update() {
	let rig = rig(60, &[]);
	let response = submit(&rig, ANN).await;
	let id = response["created"]["s1"]["id"]
		.as_str()
		.expect("id")
		.to_string();
	let answer = call(
		&rig,
		ANN,
		json!(["EmailSubmission/set", {
			"accountId": ANN,
			"update": { &id: { "undoStatus": "final" } },
		}, "c3"]),
	)
	.await;
	assert_eq!(
		answer["notUpdated"][&id]["type"], "invalidProperties",
		"{answer}"
	);
	// It is still held.
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(queued(rig.dir.path()).len(), 1);
}

#[tokio::test]
async fn with_no_delay_a_submission_is_final_at_once() {
	let rig = rig(0, &[]);
	let response = submit(&rig, ANN).await;
	let created = &response["created"]["s1"];
	assert_eq!(created["undoStatus"], "final", "{response}");
	assert!(created["sendAt"].is_null());
	assert!(response.get("updated").is_none(), "{response}");
}
