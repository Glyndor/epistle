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
use super::send_tests_class::send;
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
	let paths = by_all_three_paths(dir.path(), &policy(), "alice@example.org").await;

	// The forged fields of the draft are gone, and the marker is the
	// server's own, on every path.
	for (field, data) in [("api", &paths.api), ("jmap", &paths.jmap)] {
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
		header_values(&paths.api, "received").is_empty(),
		"the API path carried a client trace header"
	);
	assert!(
		header_values(&paths.jmap, "received").is_empty(),
		"the JMAP path carried the draft's trace header"
	);

	let from_smtp = identification(&paths.smtp);
	assert_eq!(
		from_smtp["feedback-id"],
		vec!["epistle:transactional:example.org".to_string()],
		"the SMTP path wrote no Feedback-ID: {from_smtp:?}"
	);
	for (field, values) in [
		("api", identification(&paths.api)),
		("jmap", identification(&paths.jmap)),
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

/// The same comparison for a sender that speaks for a list, where the fields
/// are not empty on any path and the list block also decides the
/// unsubscribe. A path that resolved senders against a directory without the
/// list, or dropped the block, shows up as an empty or different field here.
#[tokio::test]
async fn a_list_sender_carries_the_list_fields_on_all_three_paths() {
	let dir = tempfile::tempdir().expect("tempdir");
	let paths = by_all_three_paths(dir.path(), &policy(), "team@example.org").await;

	let from_smtp = identification(&paths.smtp);
	assert_eq!(
		from_smtp["list-id"],
		vec!["<team.example.org>".to_string()],
		"the SMTP path wrote no List-Id: {from_smtp:?}"
	);
	assert_eq!(
		from_smtp["list-post"],
		vec!["<mailto:team@example.org>".to_string()],
		"{from_smtp:?}"
	);
	assert_eq!(
		from_smtp["list-unsubscribe"],
		vec!["<mailto:team@example.org?subject=unsubscribe>".to_string()],
		"the list block and the bulk rule both wrote one: {from_smtp:?}"
	);
	for (field, values) in [
		("api", identification(&paths.api)),
		("jmap", identification(&paths.jmap)),
	] {
		assert_eq!(
			values, from_smtp,
			"the {field} path carries different identification headers than SMTP"
		);
	}
}

/// An API state whose account alice owns her own address and the list
/// address she speaks for, so the REST send-as guard admits a send as the
/// list. The directory is the one the SMTP path resolves senders against, so
/// the list is a list on all three.
fn list_state(dir: &std::path::Path) -> crate::api::ApiState {
	let domains = vec!["example.org".to_string()];
	let accounts = vec![crate::config::Account {
		display_name: None,
		name: "alice".to_string(),
		addresses: vec![
			"alice@example.org".to_string(),
			"team@example.org".to_string(),
		],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	let service = Arc::new(
		crate::evidence::service::EvidenceService::open(
			dir,
			Vec::new(),
			crate::storage::MessageCrypto::disabled(),
		)
		.expect("evidence"),
	);
	service.set_gate(None);
	let split = crate::storage::SplitDelivery::new(dir, store.handle())
		.expect("sink")
		.with_evidence(Arc::clone(&service));
	crate::api::ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store,
		FsSpool::open(dir).expect("spool"),
	)
	.with_outbound(Arc::new(split))
	.with_class_bindings(Arc::new(BindingSet::open(dir).expect("bindings")))
	.with_directory(directory())
}

/// The queued bytes each of the three paths produced for one message.
struct Paths {
	smtp: Vec<u8>,
	api: Vec<u8>,
	jmap: Vec<u8>,
}

/// The same message sent by SMTP after AUTH, by `POST /api/v1/send` and by
/// JMAP `EmailSubmission/set`, all with `sender` as the envelope sender, and
/// all three resolved against the same directory.
async fn by_all_three_paths(dir: &std::path::Path, policy: &Policy, sender: &str) -> Paths {
	update(dir, |bindings| {
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
			Arc::new(FsSpool::open(dir).expect("spool")) as Arc<dyn MessageSink>,
		)
		.with_directory(directory())
		.with_identification(policy.clone())
		.with_class_bindings(Arc::new(BindingSet::open(dir).expect("bindings")));
		let mut session = crate::smtp::session::Session::new("mail.example.org");
		session.mark_authenticated_for_test("alice");
		let mut message = AcceptedMessage {
			reverse_path: sender.to_string(),
			recipients: vec![
				"bob@elsewhere.example".to_string(),
				"carol@elsewhere.example".to_string(),
			],
			data: format!("From: {sender}\r\nSubject: s\r\n\r\nbody\r\n").into_bytes(),
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

	// The same message through the REST endpoint and through JMAP. An
	// account that owns the list address is what a real list sender looks
	// like, so the send-as guard on the REST path admits it.
	let app = router(list_state(dir).with_identification(policy.clone()));
	let (status, body) = send(
		&app,
		json!({
			"from": sender,
			"class": "transactional",
			"cc": ["carol@elsewhere.example"],
		}),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::OK, "{body}");
	let api_data = queued(dir, &body);

	let jmap_data = jmap(dir, &app, sender).await;
	Paths {
		smtp,
		api: api_data,
		jmap: jmap_data,
	}
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
async fn jmap(dir: &std::path::Path, app: &axum::Router, sender: &str) -> Vec<u8> {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let email = uuid::Uuid::now_v7();
	// A draft is the client's own message, so it can carry whatever it
	// likes, including fields that speak for the server.
	std::fs::write(
		inbox.join(format!("{email}.eml")),
		format!(
			"From: {sender}\r\n\
			 X-Epistle: 9\r\n\
			 Received: from forged.example\r\n\
			 Authentication-Results: forged.example; spf=pass\r\n\
			 Subject: s\r\n\r\nbody\r\n"
		),
	)
	.expect("write draft");
	let req = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {"accountId": "alice", "create": {"s1": {
			"emailId": email.to_string(),
			"envelope": {
				"mailFrom": {"email": sender},
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
