use axum::http::StatusCode;
use serde_json::json;

use super::super::base::{TOKEN, request_with_body};
use super::super::problem::base::{PROBLEM, call};
use super::support::{ANN, BOB, queued, rig, secret};

fn message() -> serde_json::Value {
	json!({
		"from": "ann@example.org",
		"to": ["carol@remote.example"],
		"subject": "s",
		"text": "t",
	})
}

async fn send(app: &axum::Router, token: &str) -> serde_json::Value {
	let (status, body) =
		request_with_body(app, "POST", "/api/v1/send", Some(token), Some(message())).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body
}

fn cancel_path(body: &serde_json::Value) -> String {
	format!("/api/v1/send/{}", body["queued"].as_str().expect("id"))
}

#[tokio::test]
async fn a_held_send_says_until_when_and_cancel_takes_it_back() {
	let rig = rig(60, &[]);
	let body = send(&rig.app, &secret(ANN)).await;
	assert!(body["cancel_until"].is_string(), "{body}");
	assert!(queued(rig.dir.path()).is_empty(), "nothing is queued yet");
	let (status, answer) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(ANN)),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{answer}");
	assert_eq!(answer["canceled"], body["queued"]);
	// Whatever comes after, nothing of it is delivered.
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert!(queued(rig.dir.path()).is_empty());
	// And it cannot be cancelled twice.
	let (status, _) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(ANN)),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn another_accounts_key_gets_the_answer_for_an_id_that_does_not_exist() {
	let rig = rig(60, &[]);
	let body = send(&rig.app, &secret(ANN)).await;
	let (status, other) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(BOB)),
		None,
	)
	.await;
	let (unknown_status, unknown) = request_with_body(
		&rig.app,
		"DELETE",
		&format!("/api/v1/send/{}", uuid::Uuid::now_v7()),
		Some(&secret(BOB)),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{other}");
	assert_eq!((status, other), (unknown_status, unknown));
	// The message is still held: bob's attempt took nothing back.
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(queued(rig.dir.path()).len(), 1);
}

#[tokio::test]
async fn an_unconfined_key_cancels_any_account() {
	let rig = rig(60, &[]);
	let body = send(&rig.app, &secret(ANN)).await;
	let (status, answer) =
		request_with_body(&rig.app, "DELETE", &cancel_path(&body), Some(&TOKEN), None).await;
	assert_eq!(status, StatusCode::OK, "{answer}");
}

#[tokio::test]
async fn a_message_already_handed_on_answers_409_already_sent() {
	let rig = rig(60, &[]);
	let body = send(&rig.app, &secret(ANN)).await;
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(queued(rig.dir.path()).len(), 1);
	let (status, answer) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(ANN)),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{answer}");
	assert_eq!(answer["error"]["code"], "already_sent");
	// The problem form names it too.
	let problem = call(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(ANN)),
		Some(PROBLEM),
		None,
	)
	.await;
	assert_eq!(problem.status, StatusCode::CONFLICT);
	assert_eq!(problem.body["type"], "urn:epistle:problem:already_sent");
	assert_eq!(problem.body["code"], "already_sent");
	// Bob is not told it was sent: it was not his.
	let (status, _) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(BOB)),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn with_no_delay_the_send_is_as_it_always_was() {
	let rig = rig(0, &[]);
	let body = send(&rig.app, &secret(ANN)).await;
	assert!(body.get("cancel_until").is_none(), "{body}");
	assert_eq!(queued(rig.dir.path()).len(), 1, "queued at once");
	let (status, _) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret(ANN)),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_key_that_may_only_read_cannot_cancel() {
	let rig = rig(60, &[]);
	let body = send(&rig.app, &secret(ANN)).await;
	let (status, _) = request_with_body(
		&rig.app,
		"DELETE",
		&cancel_path(&body),
		Some(&secret("ann-read")),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(queued(rig.dir.path()).len(), 1);
}

#[tokio::test]
async fn a_scope_can_turn_the_delay_off_for_one_account() {
	let rig = rig(
		60,
		&["[[queue.undo_send.scope]]\naccount = \"ann\"\ndelay_secs = 0\n"],
	);
	let body = send(&rig.app, &secret(ANN)).await;
	assert!(body.get("cancel_until").is_none(), "{body}");
	assert_eq!(queued(rig.dir.path()).len(), 1);
}
