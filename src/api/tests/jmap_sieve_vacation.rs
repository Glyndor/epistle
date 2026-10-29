//! A script managed over JMAP is the script the delivery runs, and it
//! shares the account's auto-reply with the JMAP `VacationResponse`: while
//! that is enabled it is the account's vacation and the Sieve `vacation`
//! action is ignored.

use serde_json::{Value, json};

use super::base::TOKEN;
use super::jmap_sieve_support::{app, call_as_alice, upload};
use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::storage::LocalDelivery;

const SIEVE_VACATION: &[u8] =
	b"require [\"vacation\"];\r\nvacation :days 1 :subject \"Sieve away\" \"The Sieve reply.\";\r\n";

fn delivery(dir: &std::path::Path) -> LocalDelivery {
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	LocalDelivery::new(dir, directory).expect("delivery")
}

fn inbound(sender: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.to_string(),
		recipients: vec!["alice@example.org".to_string()],
		data: b"To: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

/// What a message from `sender` is answered with.
fn replies(dir: &std::path::Path, sender: &str) -> Vec<String> {
	delivery(dir)
		.deliver_routed(&inbound(sender), None)
		.expect("deliver")
		.replies
		.iter()
		.map(|reply| String::from_utf8_lossy(&reply.data).into_owned())
		.collect()
}

async fn set(app: &axum::Router, method: &str, args: Value) -> Value {
	let mut full = json!({"accountId": "alice"});
	full.as_object_mut()
		.expect("object")
		.extend(args.as_object().expect("object").clone());
	call_as_alice(app, method, full).await
}

/// Create and activate `script` over JMAP.
async fn activate(app: &axum::Router, script: &[u8]) {
	let blob = upload(app, TOKEN.as_str(), "alice", script).await;
	let response = set(
		app,
		"SieveScript/set",
		json!({"create": {"a": {"name": "away", "blobId": blob}}, "onSuccessActivateScript": "#a"}),
	)
	.await;
	assert_eq!(response[1]["created"]["a"]["isActive"], true, "{response}");
}

async fn jmap_vacation(app: &axum::Router, update: Value) {
	let response = set(
		app,
		"VacationResponse/set",
		json!({"update": {"singleton": update}}),
	)
	.await;
	assert_eq!(
		response[1]["updated"]["singleton"],
		Value::Null,
		"{response}"
	);
}

#[tokio::test]
async fn a_sieve_vacation_activated_over_jmap_answers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	activate(&app, SIEVE_VACATION).await;
	let sent = replies(dir.path(), "carol@example.net");
	assert_eq!(sent.len(), 1);
	assert!(sent[0].contains("The Sieve reply."), "{}", sent[0]);
}

#[tokio::test]
async fn while_the_jmap_vacation_is_enabled_it_is_the_only_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	activate(&app, SIEVE_VACATION).await;
	jmap_vacation(
		&app,
		json!({"isEnabled": true, "subject": "JMAP away", "textBody": "The JMAP reply."}),
	)
	.await;
	let sent = replies(dir.path(), "dave@example.net");
	assert_eq!(sent.len(), 1, "one reply, not two");
	assert!(sent[0].contains("The JMAP reply."), "{}", sent[0]);
	assert!(!sent[0].contains("The Sieve reply."));
}

#[tokio::test]
async fn outside_the_jmap_window_the_sieve_vacation_does_not_fill_in() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	activate(&app, SIEVE_VACATION).await;
	jmap_vacation(
		&app,
		json!({"isEnabled": true, "textBody": "Back soon.", "toDate": "2020-01-01T00:00:00Z"}),
	)
	.await;
	assert_eq!(
		replies(dir.path(), "erin@example.net"),
		Vec::<String>::new()
	);
}

#[tokio::test]
async fn once_the_jmap_vacation_is_off_the_sieve_vacation_answers_again() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	activate(&app, SIEVE_VACATION).await;
	jmap_vacation(
		&app,
		json!({"isEnabled": true, "textBody": "The JMAP reply."}),
	)
	.await;
	jmap_vacation(&app, json!({"isEnabled": false})).await;
	let sent = replies(dir.path(), "frank@example.net");
	assert_eq!(sent.len(), 1);
	assert!(sent[0].contains("The Sieve reply."), "{}", sent[0]);
}

#[tokio::test]
async fn deactivating_the_script_over_jmap_stops_its_vacation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	activate(&app, SIEVE_VACATION).await;
	set(
		&app,
		"SieveScript/set",
		json!({"onSuccessDeactivateScript": true}),
	)
	.await;
	assert_eq!(
		replies(dir.path(), "gina@example.net"),
		Vec::<String>::new()
	);
}

#[tokio::test]
async fn a_script_of_many_redirects_activated_over_jmap_forwards_to_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let script: String = (0..200)
		.map(|n| format!("redirect :copy \"user{n}@target.example\";\r\n"))
		.collect();
	activate(&app, script.as_bytes()).await;
	let delivered = delivery(dir.path())
		.deliver_routed(&inbound("henry@example.net"), None)
		.expect("deliver");
	assert_eq!(
		delivered.redirects.len(),
		crate::sieve::interp::MAX_REDIRECTS
	);
	assert!(
		delivered
			.redirects
			.iter()
			.all(|r| r.to.ends_with("@target.example"))
	);
}
