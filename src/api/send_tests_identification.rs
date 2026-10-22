//! The same message carries the same identification headers whichever of
//! the three submission paths sent it: SMTP after AUTH, `POST /api/v1/send`
//! and JMAP `EmailSubmission/set`.
//!
//! One message, one policy, three paths, one comparison. A path that
//! stopped passing its policy to `evidence::submission::prepare`, or built
//! the fields itself, would make the three sets differ and this fails.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};

use super::router;
use super::send_tests_class::{send, state};
use super::tests::{TOKEN, request_with_body};
use crate::evidence::MailClass;
use crate::evidence::bindings::{BindingSet, update};
use crate::smtp::identification::Policy;
use crate::smtp::server::Server;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MessageSink;
use crate::smtp::trace::header_values;
use crate::storage::FsSpool;

/// The fields this test compares, in the order they are compared.
const FIELDS: &[&str] = &[
	"x-epistle",
	"organization",
	"feedback-id",
	"list-id",
	"list-post",
	"list-unsubscribe",
];

/// A policy every switch is on, so one missing path shows up as a missing
/// field rather than as a field nobody set.
fn policy() -> Policy {
	let mut organization = BTreeMap::new();
	organization.insert("example.org".to_string(), "Example Org".to_string());
	Policy {
		x_epistle: true,
		bulk_recipients: 1,
		domain_organization: organization,
		..Policy::default()
	}
}

/// The value of every field in [`FIELDS`] the message carries.
fn identification(data: &[u8]) -> BTreeMap<&str, Vec<String>> {
	FIELDS
		.iter()
		.map(|field| (*field, header_values(data, field)))
		.collect()
}

/// One message from each of the three paths, all the same message.
#[tokio::test]
async fn the_same_message_carries_the_same_fields_by_all_three_paths() {
	let dir = tempfile::tempdir().expect("tempdir");
	let policy = policy();
	update(dir.path(), |bindings| {
		bindings
			.accounts
			.insert("alice".to_string(), MailClass::Transactional);
	})
	.expect("bind the account class");

	// SMTP after AUTH: the server's own hook, with the policy the server
	// was configured with.
	let smtp = {
		let server = Server::new(
			"mail.example.org",
			Arc::new(crate::storage::FsSpool::open(dir.path()).expect("spool"))
				as Arc<dyn MessageSink>,
		)
		.with_directory(directory())
		.with_identification(policy.clone())
		.with_class_bindings(Arc::new(BindingSet::open(dir.path()).expect("bindings")));
		let mut session = crate::smtp::session::Session::new("mail.example.org");
		session.mark_authenticated_for_test("alice");
		let mut message = AcceptedMessage {
			reverse_path: "alice@example.org".to_string(),
			recipients: vec![
				"bob@elsewhere.example".to_string(),
				"carol@elsewhere.example".to_string(),
			],
			data: b"From: alice@example.org\r\nSubject: s\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: true,
			no_dsn: Vec::new(),
		};
		server
			.prepare_submission(&session, "alice", &mut message)
			.expect("prepared");
		message.data
	};

	// The same message through the REST endpoint and through JMAP.
	let (api, _) = state(dir.path());
	let app = router(api.with_identification(policy.clone()));
	let (status, body) = send(
		&app,
		json!({
			"class": "transactional",
			"cc": ["carol@elsewhere.example"],
		}),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	let api_data = queued(dir.path(), &body);

	let jmap_data = jmap(dir.path(), &app).await;

	// The forged fields of the draft are gone, and the marker is the
	// server's own, on every path.
	for (field, data) in [("api", &api_data), ("jmap", &jmap_data)] {
		assert_eq!(
			header_values(data, "x-epistle"),
			vec!["1".to_string()],
			"the {field} path kept a client marker"
		);
		assert!(
			header_values(data, "authentication-results").is_empty(),
			"the {field} path kept a forged Authentication-Results"
		);
	}
	assert!(
		header_values(&api_data, "received").is_empty(),
		"the API path carried a client trace header"
	);
	assert!(
		header_values(&jmap_data, "received").is_empty(),
		"the JMAP path carried the draft's trace header"
	);

	let from_smtp = identification(&smtp);
	assert_eq!(
		from_smtp["feedback-id"],
		vec!["epistle:transactional:example.org".to_string()],
		"the SMTP path wrote no Feedback-ID: {from_smtp:?}"
	);
	for (field, values) in [
		("api", identification(&api_data)),
		("jmap", identification(&jmap_data)),
	] {
		assert_eq!(
			values, from_smtp,
			"the {field} path carries different identification headers than SMTP"
		);
	}
	assert_eq!(
		from_smtp["list-unsubscribe"],
		vec!["<mailto:alice@example.org?subject=unsubscribe>".to_string()],
		"{from_smtp:?}"
	);
	assert_eq!(
		from_smtp["x-epistle"],
		vec!["1".to_string()],
		"{from_smtp:?}"
	);
	assert_eq!(
		from_smtp["organization"],
		vec!["Example Org".to_string()],
		"{from_smtp:?}"
	);
}

/// The queued bytes of the message a `POST /api/v1/send` queued.
fn queued(dir: &std::path::Path, body: &Value) -> Vec<u8> {
	let id = uuid::Uuid::parse_str(body["queued"].as_str().expect("id")).expect("uuid");
	FsSpool::open(dir)
		.expect("spool")
		.load(id)
		.expect("queued")
		.data
}

/// Submit the same message through JMAP `EmailSubmission/set` and return
/// the queued bytes.
async fn jmap(dir: &std::path::Path, app: &axum::Router) -> Vec<u8> {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let email = uuid::Uuid::now_v7();
	// A draft is the client's own message, so it can carry whatever it
	// likes, including fields that speak for the server.
	std::fs::write(
		inbox.join(format!("{email}.eml")),
		b"From: alice@example.org\r\n\
		  X-Epistle: 9\r\n\
		  Received: from forged.example\r\n\
		  Authentication-Results: forged.example; spf=pass\r\n\
		  Subject: s\r\n\r\nbody\r\n",
	)
	.expect("write draft");
	let req = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {"accountId": "alice", "create": {"s1": {
			"emailId": email.to_string(),
			"envelope": {
				"mailFrom": {"email": "alice@example.org"},
				"rcptTo": [
					{"email": "bob@elsewhere.example"},
					{"email": "carol@elsewhere.example"},
				],
			},
			"epistle:class": "transactional",
		}}}, "c1"]],
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	let id = body["methodResponses"][0][1]["created"]["s1"]["id"]
		.as_str()
		.expect("created")
		.to_string();
	FsSpool::open(dir)
		.expect("spool")
		.load(uuid::Uuid::parse_str(&id).expect("uuid"))
		.expect("queued")
		.data
}

/// The directory both paths resolve senders and lists against: one account
/// and the list it speaks for.
fn directory() -> crate::directory_store::DirectoryHandle {
	crate::directory_store::DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("team@example.org".to_string(), "alice".to_string()),
			],
		)
		.with_aliases([(
			"team@example.org".to_string(),
			crate::smtp::directory::AliasSpec {
				members: vec!["alice@example.org".to_string()],
				senders: Vec::new(),
				hidden: false,
				list_id: Some("team.example.org".to_string()),
			},
		)]),
	)
}
