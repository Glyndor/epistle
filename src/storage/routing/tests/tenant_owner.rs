//! The other ways into the outbound queue name an owner too, from what the
//! server resolved: the authenticated account's domain.

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

fn message(sender: &str, recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.into(),
		recipients: vec![recipient.into()],
		data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn only_owner(root: &std::path::Path) -> Option<String> {
	let spool = FsSpool::open(root).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	spool.load(ids[0]).expect("entry").envelope.owner
}

#[test]
fn a_submit_through_the_spool_is_owned_by_the_accounts_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path())
		.expect("spool")
		.with_owner_directory(two_domains());
	spool
		.submit(
			message("ceo@a.example", "carol@remote.example"),
			uuid::Uuid::now_v7(),
			"bob",
			&Submission::default(),
		)
		.expect("accepted");
	// Bob, of b.example, wrote a sender in a.example: the entry is bob's.
	assert_eq!(only_owner(dir.path()).as_deref(), Some("b.example"));
}

#[test]
fn a_submit_through_the_spool_without_a_directory_has_no_owner() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.submit(
			message("bob@b.example", "carol@remote.example"),
			uuid::Uuid::now_v7(),
			"bob",
			&Submission::default(),
		)
		.expect("accepted");
	assert_eq!(only_owner(dir.path()), None);
}

fn srs_sink(dir: &std::path::Path) -> (SplitDelivery, String) {
	let secret = fresh_secret();
	let srs = crate::queue::srs::Srs::new(secret.as_bytes());
	let now_days = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0);
	let local = srs
		.forward("origsender", "origin.example", "relay.example", now_days)
		.split_once('@')
		.expect("an address")
		.0
		.to_string();
	let sink = SplitDelivery::new(dir, two_domains())
		.expect("sink")
		.with_srs(
			crate::queue::srs::Srs::new(secret.as_bytes()),
			"relay.example",
		);
	(sink, format!("{local}@relay.example"))
}

#[test]
fn an_srs_return_queued_for_an_authenticated_account_is_owned_by_its_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (sink, address) = srs_sink(dir.path());
	sink.submit(
		message("", &address),
		uuid::Uuid::now_v7(),
		"bob",
		&Submission::default(),
	)
	.expect("accepted");
	assert_eq!(only_owner(dir.path()).as_deref(), Some("b.example"));
}

#[test]
fn an_srs_return_with_no_authenticated_account_has_no_owner() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (sink, address) = srs_sink(dir.path());
	sink.deliver(message("", &address)).expect("accepted");
	assert_eq!(only_owner(dir.path()), None);
}
