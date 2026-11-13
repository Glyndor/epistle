//! What a local delivery queues for a recipient of another tenant does not
//! carry the sender's account or correlation map.

use super::*;
use crate::smtp::sink::{MessageSink, Submission};
use crate::test_support::fixtures::fresh_secret;

fn two_domains() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["a.example".to_string(), "b.example".to_string()],
		[
			("alice@a.example".to_string(), "alice".to_string()),
			("bob@b.example".to_string(), "bob".to_string()),
		],
	))
}

fn mail_for(recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "origin@elsewhere.example".into(),
		recipients: vec![recipient.into()],
		data: b"Subject: ping\r\n\r\nhi\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn reject_all(root: &std::path::Path, account: &str) {
	let dir = root.join("accounts").join(account);
	std::fs::create_dir_all(&dir).expect("mkdir");
	std::fs::write(dir.join("filter.sieve"), "reject \"no thanks\";").expect("filter");
}

#[test]
fn a_refusal_for_another_tenants_recipient_holds_nothing_of_the_senders() {
	let dir = tempfile::tempdir().expect("tempdir");
	reject_all(dir.path(), "bob");
	let sink = SplitDelivery::new(dir.path(), two_domains()).expect("sink");
	// Alice, of a.example, writes to bob, of b.example, with a correlation map
	// of her own application.
	let marker = fresh_secret();
	let mut submission = Submission::default();
	submission.extra.insert("app".into(), marker.clone());
	sink.submit(
		mail_for("bob@b.example"),
		uuid::Uuid::now_v7(),
		"alice",
		&submission,
	)
	.expect("accepted");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let envelope = spool.load(ids[0]).expect("entry").envelope;
	assert_eq!(envelope.owner.as_deref(), Some("b.example"));
	assert!(
		envelope.extra.is_empty(),
		"the refusal inherited another tenant's map"
	);
	assert_eq!(envelope.account, None);
	assert!(
		!serde_json::to_string(&envelope)
			.expect("json")
			.contains(&marker)
	);
}

#[test]
fn a_refusal_for_the_senders_own_domain_keeps_her_attribution() {
	let dir = tempfile::tempdir().expect("tempdir");
	reject_all(dir.path(), "alice");
	let sink = SplitDelivery::new(dir.path(), two_domains()).expect("sink");
	let marker = fresh_secret();
	let mut submission = Submission::default();
	submission.extra.insert("app".into(), marker.clone());
	sink.submit(
		mail_for("alice@a.example"),
		uuid::Uuid::now_v7(),
		"alice",
		&submission,
	)
	.expect("accepted");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let envelope = spool
		.load(spool.list().expect("list")[0])
		.expect("entry")
		.envelope;
	assert_eq!(envelope.owner.as_deref(), Some("a.example"));
	assert_eq!(envelope.extra.get("app"), Some(&marker));
	assert_eq!(envelope.account.as_deref(), Some("alice"));
}
