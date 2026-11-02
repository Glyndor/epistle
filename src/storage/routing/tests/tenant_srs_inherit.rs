//! An SRS return that a hosted domain takes over does not carry the account or
//! the correlation map of an ownerless submission.

use super::*;
use crate::queue::srs::{Srs, SrsKeys};
use crate::smtp::sink::{MessageSink, Submission};
use crate::test_fixtures::fresh_secret;

/// `multi` has addresses in two domains, so it has no single owner.
fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["a.example".to_string(), "b.example".to_string()],
		[
			("multi@a.example".to_string(), "multi".to_string()),
			("multi@b.example".to_string(), "multi".to_string()),
			("alice@a.example".to_string(), "alice".to_string()),
		],
	))
}

fn bounce(to: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![to.into()],
		data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn sink_and_address(root: &std::path::Path) -> (SplitDelivery, String) {
	let secret = fresh_secret();
	let now_days = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0);
	let keys = || SrsKeys::default().with_domain("a.example", Srs::new(secret.as_bytes()), None);
	let local = keys()
		.forward(
			"a.example",
			("origsender", "origin.example"),
			"relay.example",
			now_days,
		)
		.expect("signed");
	let sink = SplitDelivery::new(root, directory())
		.expect("sink")
		.with_srs_keys(keys(), "relay.example");
	(
		sink,
		format!(
			"{}@relay.example",
			local.split_once('@').expect("address").0
		),
	)
}

fn the_only_entry(root: &std::path::Path) -> crate::storage::Envelope {
	let spool = FsSpool::open(root).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	spool.load(ids[0]).expect("entry").envelope
}

#[test]
fn an_ownerless_submission_hands_the_domain_that_signed_nothing_of_its_own() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (sink, address) = sink_and_address(dir.path());
	let marker = fresh_secret();
	let mut submission = Submission::default();
	submission.extra.insert("app".into(), marker.clone());
	// `multi` authenticates, but sits in two domains: no single owner.
	sink.submit(bounce(&address), uuid::Uuid::now_v7(), "multi", &submission)
		.expect("accepted");
	let entry = the_only_entry(dir.path());
	assert_eq!(entry.owner.as_deref(), Some("a.example"));
	assert!(
		entry.extra.is_empty(),
		"a.example was handed another account's map"
	);
	assert_eq!(entry.account, None);
	assert!(
		!serde_json::to_string(&entry)
			.expect("json")
			.contains(&marker)
	);
}

#[test]
fn the_accounts_own_domain_keeps_its_attribution() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (sink, address) = sink_and_address(dir.path());
	let marker = fresh_secret();
	let mut submission = Submission::default();
	submission.extra.insert("app".into(), marker.clone());
	sink.submit(bounce(&address), uuid::Uuid::now_v7(), "alice", &submission)
		.expect("accepted");
	let entry = the_only_entry(dir.path());
	assert_eq!(entry.owner.as_deref(), Some("a.example"));
	assert_eq!(entry.extra.get("app"), Some(&marker));
	assert_eq!(entry.account.as_deref(), Some("alice"));
}
