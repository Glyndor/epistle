//! Sieve actions and SRS rewriting applied while routing.

use super::base::{directory, inbox_count, message, spool_count};
use super::*;
use std::fs;

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
fn sieve_reject_with_notify_never_sends_no_bounce() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(account_dir.join("filter.sieve"), "reject \"no thanks\";").expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let mut msg = message(&["alice@example.org"]);
	msg.no_dsn = vec!["alice@example.org".to_string()];
	sink.deliver(msg).expect("deliver");
	// Rejected, but the sender opted out of failure DSNs: nothing is queued.
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	assert_eq!(spool_count(dir.path()), 0);
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
	msg.data = b"To: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
	msg.sender_verified = true;
	let again = msg.clone();
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
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
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
