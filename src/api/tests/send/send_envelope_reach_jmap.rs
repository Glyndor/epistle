//! `EmailSubmission/set` asks the same questions about the senders of a
//! message as `POST /api/v1/send`: the envelope sender, the `From` field and
//! the `Sender` field are each judged against the domains of the key as well
//! as against the account. `alice` owns `ops@other.example` as a member of a
//! list, so only the rule under test can refuse it.

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::send_envelope_reach::{CONFINED, add_confined_key, directory, limited, queued};
use crate::directory_store::DirectoryHandle;

fn app(dir: &std::path::Path) -> Router {
	add_confined_key(dir);
	router(test_state(dir, 0).with_directory(DirectoryHandle::new(directory())))
}

/// Store a draft in alice's mailbox with `headers` and submit it, with
/// `mail_from` as the envelope sender when there is one; the response to the
/// one submission.
async fn submit(
	app: &Router,
	dir: &std::path::Path,
	token: &str,
	headers: &str,
	mail_from: Option<Value>,
) -> Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!("{headers}To: dest@remote.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	)
	.expect("write");
	let mut submission = json!({ "emailId": id.to_string() });
	if let Some(mail_from) = mail_from {
		submission["envelope"] = json!({
			"mailFrom": {"email": mail_from},
			"rcptTo": [{"email": "dest@remote.example"}],
		});
	}
	let request = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice", "create": { "s1": submission },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(token), Some(request)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

fn created(response: &Value) -> bool {
	response["created"]["s1"]["id"].is_string()
}

const OWN: &str = "From: alice@example.org\r\n";
const FOREIGN_FROM: &str = "From: ops@other.example\r\n";

#[tokio::test]
async fn every_sender_of_a_submission_is_held_to_the_domains_of_the_key() {
	// Each case sends under `ops@other.example` somewhere: the envelope, the
	// author, the `Sender` field, or the sender a missing envelope falls
	// back to.
	let cases: [(&str, &str, Option<Value>); 4] = [
		("envelope", OWN, Some(json!("ops@other.example"))),
		("from", FOREIGN_FROM, Some(json!("alice@example.org"))),
		(
			"sender",
			"From: alice@example.org\r\nSender: ops@other.example\r\n",
			Some(json!("alice@example.org")),
		),
		("from without an envelope", FOREIGN_FROM, None),
	];
	for (name, headers, mail_from) in cases {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		// The same submission from the unconfined token goes out: the account
		// does own the address, so only the key's domains refuse it.
		let response = submit(&app, dir.path(), TOKEN.as_str(), headers, mail_from.clone()).await;
		assert!(created(&response), "{name}: {response}");
		let before = queued(dir.path());
		let response = submit(&app, dir.path(), CONFINED, headers, mail_from).await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenFrom",
			"{name}: {response}"
		);
		assert_eq!(queued(dir.path()), before, "{name}: nothing was queued");
	}
}

#[tokio::test]
async fn a_key_with_domains_has_no_null_reverse_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = submit(&app, dir.path(), CONFINED, OWN, Some(json!(""))).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "forbiddenFrom",
		"{response}"
	);
	// The unconfined token keeps the bounce sender.
	let response = submit(&app, dir.path(), TOKEN.as_str(), OWN, Some(json!(""))).await;
	assert!(created(&response), "{response}");
}

#[tokio::test]
async fn a_key_with_domains_submits_under_its_own_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let own_sender = "From: alice@example.org\r\nSender: alice@example.org\r\n";
	for (headers, mail_from) in [
		(OWN, Some(json!("alice@example.org"))),
		(OWN, None),
		(own_sender, Some(json!("alice@example.org"))),
	] {
		let response = submit(&app, dir.path(), CONFINED, headers, mail_from).await;
		assert!(created(&response), "{response}");
	}
}

#[tokio::test]
async fn the_sender_field_is_held_to_the_account_as_the_rest_route_does() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let stranger = "From: alice@example.org\r\nSender: stranger@elsewhere.example\r\n";
	let response = submit(
		&app,
		dir.path(),
		TOKEN.as_str(),
		stranger,
		Some(json!("alice@example.org")),
	)
	.await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "forbiddenFrom",
		"{response}"
	);
	let owned = "From: alice@example.org\r\nSender: ops@other.example\r\n";
	let response = submit(
		&app,
		dir.path(),
		TOKEN.as_str(),
		owned,
		Some(json!("alice@example.org")),
	)
	.await;
	assert!(created(&response), "{response}");
}

/// Every `Sender` field is read, and every address of each, as the From field
/// is: a second field, or a second address in one, is held to the key and to
/// the account like the first.
#[tokio::test]
async fn every_sender_field_and_address_of_a_submission_is_checked() {
	let cases = [
		(
			"a second field",
			"From: alice@example.org\r\nSender: alice@example.org\r\nSender: ops@other.example\r\n",
			"ops@other.example is the second field and outside the key",
		),
		(
			"a list",
			"From: alice@example.org\r\nSender: alice@example.org, ops@other.example\r\n",
			"ops@other.example is the second address and outside the key",
		),
	];
	for (name, headers, why) in cases {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		// The account owns every address, so the unconfined token sends it.
		let response = submit(
			&app,
			dir.path(),
			TOKEN.as_str(),
			headers,
			Some(json!("alice@example.org")),
		)
		.await;
		assert!(created(&response), "{name}: {response}");
		let response = submit(
			&app,
			dir.path(),
			CONFINED,
			headers,
			Some(json!("alice@example.org")),
		)
		.await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenFrom",
			"{name}: {why}: {response}"
		);
	}
	// And one the account does not own, in the second field, is refused to all.
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let headers = "From: alice@example.org\r\nSender: alice@example.org\r\nSender: stranger@elsewhere.example\r\n";
	let response = submit(
		&app,
		dir.path(),
		TOKEN.as_str(),
		headers,
		Some(json!("alice@example.org")),
	)
	.await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "forbiddenFrom",
		"{response}"
	);
}

/// A `Sender` field that names no address cannot have been checked, so the
/// submission is refused rather than passed on the strength of an empty list.
#[tokio::test]
async fn a_sender_field_that_names_no_address_is_refused() {
	for sender in [",,,", "()", "<>"] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		let headers = format!("From: alice@example.org\r\nSender: {sender}\r\n");
		let response = submit(
			&app,
			dir.path(),
			TOKEN.as_str(),
			&headers,
			Some(json!("alice@example.org")),
		)
		.await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenFrom",
			"Sender: {sender}: {response}"
		);
	}
}

#[tokio::test]
async fn every_tenant_a_submission_is_sent_under_is_charged() {
	// `ops@other.example` belongs to a tenant that may send one recipient a
	// minute, and each case names it in one place only, but the last, where
	// the missing envelope takes its sender from the author.
	let cases: [(&str, &str, Option<Value>); 4] = [
		("envelope", OWN, Some(json!("ops@other.example"))),
		("from", FOREIGN_FROM, Some(json!("alice@example.org"))),
		(
			"sender",
			"From: alice@example.org\r\nSender: ops@other.example\r\n",
			Some(json!("alice@example.org")),
		),
		("from without an envelope", FOREIGN_FROM, None),
	];
	for (name, headers, mail_from) in cases {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = limited(dir.path());
		let response = submit(&app, dir.path(), TOKEN.as_str(), headers, mail_from.clone()).await;
		assert!(created(&response), "{name}: {response}");
		let before = queued(dir.path());
		let response = submit(&app, dir.path(), TOKEN.as_str(), headers, mail_from).await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "rateLimit",
			"{name}: tenant b is spent: {response}"
		);
		assert_eq!(queued(dir.path()), before, "{name}: nothing was queued");
	}
}

#[tokio::test]
async fn a_submission_under_the_account_own_domain_does_not_touch_the_other_tenant() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = limited(dir.path());
	for _ in 0..3 {
		let response = submit(
			&app,
			dir.path(),
			TOKEN.as_str(),
			OWN,
			Some(json!("alice@example.org")),
		)
		.await;
		assert!(created(&response), "{response}");
	}
}
