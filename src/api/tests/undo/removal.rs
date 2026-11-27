//! Removing an account whose submissions are held by the send delay: with
//! the queue discarded nothing it entrusted to the server leaves after it is
//! gone, with it kept the held submissions go out as they would have, and the
//! counts say which.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::base::{TOKEN, request_with_body};
use super::support::{ANN, queued, rig, secret};
use crate::directory_store::DynamicAccount;

/// A dynamic account, which can be removed, with an address of its own.
fn add_dana(rig: &super::support::Rig) {
	rig.store
		.add(DynamicAccount {
			name: "dana".to_string(),
			addresses: vec!["dana@example.org".to_string()],
			password_hash: "$argon2id$secret".to_string(),
			..DynamicAccount::default()
		})
		.expect("add dana");
}

/// Send as `from` through the configured token, which reaches every account;
/// the answer.
async fn send_as(rig: &super::support::Rig, from: &str, token: &str) -> Value {
	let (status, body) = request_with_body(
		&rig.app,
		"POST",
		"/api/v1/send",
		Some(token),
		Some(json!({
			"from": from, "to": ["carol@remote.example"], "subject": "s", "text": "t",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(body["cancel_until"].is_string(), "{body}");
	body
}

async fn remove_dana(rig: &super::support::Rig, queue: &str) -> Value {
	let (status, body) = request_with_body(
		&rig.app,
		"DELETE",
		&format!("/api/v1/accounts/dana?queue={queue}"),
		Some(TOKEN.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body
}

#[tokio::test]
async fn discarding_the_queue_takes_back_what_the_account_held() {
	let rig = rig(60, &[]);
	add_dana(&rig);
	send_as(&rig, "dana@example.org", TOKEN.as_str()).await;
	send_as(&rig, "ann@example.org", &secret(ANN)).await;
	let removed = remove_dana(&rig, "discard").await;
	assert_eq!(removed["queued_messages_discarded"], 1, "{removed}");
	assert_eq!(removed["queued_messages_left"], 0, "{removed}");
	// Whatever time comes, only the other account's message goes.
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(
		queued(rig.dir.path()).len(),
		1,
		"ann's goes, dana's does not"
	);
}

#[tokio::test]
async fn keeping_the_queue_lets_the_held_submissions_go_out_and_counts_them() {
	let rig = rig(60, &[]);
	add_dana(&rig);
	send_as(&rig, "dana@example.org", TOKEN.as_str()).await;
	let removed = remove_dana(&rig, "drain").await;
	assert_eq!(removed["queued_messages_discarded"], 0, "{removed}");
	assert_eq!(removed["queued_messages_left"], 1, "{removed}");
	rig.releaser.release_due(u64::MAX / 2).expect("pass");
	assert_eq!(queued(rig.dir.path()).len(), 1);
}
