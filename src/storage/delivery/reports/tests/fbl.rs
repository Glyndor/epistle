//! The feedback-loop hook of local delivery: a complaint delivered to the
//! named mailbox suppresses the complainant, and still lands in the mailbox.

use super::*;
use crate::directory_store::DirectoryHandle;
use crate::reports::fbl::Fbl;
use crate::reports::fbl::test_support::{HOSTNAME, reports, stamp, valid_report};
use crate::smtp::sink::MessageSink;
use crate::storage::LocalDelivery;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("fbl@example.org".to_string(), "fbl".to_string()),
		],
	))
}

fn report() -> Vec<u8> {
	valid_report("victim@example.com")
}

fn sink(dir: &std::path::Path, fbl: bool) -> LocalDelivery {
	LocalDelivery::new(dir, directory())
		.expect("delivery")
		.with_fbl(
			fbl.then(|| Fbl::new(&reports(""), HOSTNAME, vec!["s1".to_string()]))
				.flatten(),
		)
}

fn message(recipient: &str, verified: bool) -> AcceptedMessage {
	// An unproved report carries no stamp of this server's.
	let stamp = if verified {
		stamp(Some("arf.example.net"), None)
	} else {
		String::new()
	};
	let mut data = stamp.into_bytes();
	data.extend_from_slice(&report());
	AcceptedMessage {
		reverse_path: "fbl@arf.example.net".into(),
		recipients: vec![recipient.into()],
		data,
		sender_verified: true,
		..AcceptedMessage::default()
	}
}

#[test]
fn a_complaint_to_the_mailbox_suppresses_and_is_still_delivered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = sink(dir.path(), true);
	sink.deliver(message("fbl@example.org", true))
		.expect("deliver");
	let list = crate::queue::suppression::SuppressionList::open(dir.path()).expect("list");
	assert!(list.is_suppressed_for("alice", "victim@example.com"));
	let inbox = dir.path().join("accounts/fbl");
	assert!(inbox.exists(), "the mailbox copy still lands");
}

#[test]
fn the_same_report_to_another_mailbox_does_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = sink(dir.path(), true);
	sink.deliver(message("alice@example.org", true))
		.expect("deliver");
	let list = crate::queue::suppression::SuppressionList::open(dir.path()).expect("list");
	assert!(list.entries_for("alice").is_empty());
}

#[test]
fn without_a_configured_mailbox_nothing_is_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = sink(dir.path(), false);
	sink.deliver(message("fbl@example.org", true))
		.expect("deliver");
	let list = crate::queue::suppression::SuppressionList::open(dir.path()).expect("list");
	assert!(list.entries_for("alice").is_empty());
}

#[test]
fn an_unverified_sender_suppresses_nobody() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = sink(dir.path(), true);
	sink.deliver(message("fbl@example.org", false))
		.expect("deliver");
	let list = crate::queue::suppression::SuppressionList::open(dir.path()).expect("list");
	assert!(list.entries_for("alice").is_empty());
}
