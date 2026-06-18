//! Tests for delivery routing (SplitDelivery).

use super::*;
use std::fs;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

fn message(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
	}
}

fn inbox_count(root: &std::path::Path, account: &str) -> usize {
	fs::read_dir(root.join("accounts").join(account).join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0)
}

fn spool_count(root: &std::path::Path) -> usize {
	FsSpool::open(root)
		.expect("open spool")
		.list()
		.expect("list")
		.len()
}

fn folder_count(root: &std::path::Path, account: &str, mailbox: &str) -> usize {
	fs::read_dir(
		root.join("accounts")
			.join(account)
			.join("folders")
			.join(mailbox)
			.join("new"),
	)
	.map(|entries| entries.count())
	.unwrap_or(0)
}

#[test]
fn junk_rule_files_into_the_junk_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let rule = crate::rules::Rule {
		sender_domain: Some("example.org".to_string()),
		header: None,
		header_contains: None,
		junk: true,
		mailbox: None,
	};
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_rules(vec![rule]);
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// Routed to Junk, not INBOX.
	assert_eq!(folder_count(dir.path(), "alice", "Junk"), 1);
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
}

#[test]
fn explicit_mailbox_hint_quarantines_to_that_folder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let mut msg = message(&["alice@example.org"]);
	msg.mailbox = Some("Rejects".to_string());
	sink.deliver(msg).expect("deliver");
	assert_eq!(folder_count(dir.path(), "alice", "Rejects"), 1);
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
}

#[test]
fn sieve_reject_bounces_and_skips_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(account_dir.join("filter.sieve"), "reject \"no thanks\";").expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// Rejected: nothing delivered, one DSN bounce queued to the sender.
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	// A DSN uses the null reverse-path and goes to the original sender.
	assert!(
		entry.envelope.reverse_path.is_empty(),
		"{:?}",
		entry.envelope
	);
	assert_eq!(
		entry.envelope.recipients,
		vec!["alice@example.org".to_string()]
	);
}

#[test]
fn sieve_vacation_replies_once_and_keeps() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(account_dir.join("filter.sieve"), "vacation \"I am away\";").expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");

	let mut msg = message(&["alice@example.org"]);
	msg.reverse_path = "bob@example.net".into();
	sink.deliver(msg).expect("deliver");
	// Kept in INBOX, one null-sender autoresponse queued to the sender.
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let reply = spool.load(ids[0]).expect("load");
	assert!(reply.envelope.reverse_path.is_empty(), "null sender");
	assert_eq!(
		reply.envelope.recipients,
		vec!["bob@example.net".to_string()]
	);

	// A second message from the same sender is deduped: no new reply.
	let mut again = message(&["alice@example.org"]);
	again.reverse_path = "bob@example.net".into();
	sink.deliver(again).expect("deliver");
	assert_eq!(spool.list().expect("list").len(), 1);
}

#[test]
fn sieve_redirect_queues_to_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(
		account_dir.join("filter.sieve"),
		"redirect \"forward@example.com\";",
	)
	.expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// Redirect cancels the implicit keep: nothing in INBOX, one in the spool.
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	assert_eq!(
		entry.envelope.recipients,
		vec!["forward@example.com".to_string()]
	);
}

#[test]
fn srs_rewrites_the_forwarded_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(
		account_dir.join("filter.sieve"),
		"redirect \"forward@example.com\";",
	)
	.expect("filter");
	let srs = crate::queue::srs::Srs::new(b"test secret");
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs(srs, "relay.example");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	// The forwarded sender is rewritten to an SRS address at our domain.
	assert!(
		entry.envelope.reverse_path.starts_with("SRS0="),
		"{}",
		entry.envelope.reverse_path
	);
	assert!(entry.envelope.reverse_path.ends_with("@relay.example"));
}

#[test]
fn srs_return_address_forwards_to_original_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let srs = crate::queue::srs::Srs::new(b"test secret");
	// Encode an SRS-return address for the original sender at our domain.
	let now_days = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0);
	let srs_local = srs
		.forward("origsender", "origin.example", "relay.example", now_days)
		.split_once('@')
		.unwrap()
		.0
		.to_string();
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs(crate::queue::srs::Srs::new(b"test secret"), "relay.example");

	let bounce = AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![format!("{srs_local}@relay.example")],
		data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
	};
	sink.deliver(bounce).expect("deliver");
	// The bounce is re-queued to the original sender it encoded.
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	assert_eq!(
		entry.envelope.recipients,
		vec!["origsender@origin.example".to_string()]
	);
}

#[test]
fn local_only_message_skips_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
	assert_eq!(spool_count(dir.path()), 0);
}

#[test]
fn remote_only_message_goes_to_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["bob@elsewhere.example"]))
		.expect("deliver");
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	assert_eq!(spool_count(dir.path()), 1);
}

#[test]
fn mixed_message_is_split() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org", "bob@elsewhere.example"]))
		.expect("deliver");
	assert_eq!(inbox_count(dir.path(), "alice"), 1);

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	// Only the remote recipient is queued for outbound delivery.
	assert_eq!(
		entry.envelope.recipients,
		vec!["bob@elsewhere.example".to_string()]
	);
}

#[test]
fn unknown_local_user_fails_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let result = sink.deliver(message(&["stranger@example.org"]));
	assert!(result.is_err());
	assert_eq!(spool_count(dir.path()), 0);
}
