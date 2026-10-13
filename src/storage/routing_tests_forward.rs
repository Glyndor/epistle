//! What the routing sink queues for a forwarding delivery: the forwarded
//! copy names the forwarding address in `Delivered-To`, and a copy that
//! comes back is bounced with 5.4.6 instead of going round again.

use super::*;
use crate::storage::FsSpool;

fn sink(dir: &std::path::Path) -> SplitDelivery {
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_forwards([(
			"alice".to_string(),
			(vec!["ext@other.example".to_string()], false),
		)]),
	);
	SplitDelivery::new(dir, directory).expect("sink")
}

fn inbound(data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "s@x.example".into(),
		recipients: vec!["alice@example.org".into()],
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	}
}

fn queued(dir: &std::path::Path) -> Vec<crate::storage::SpoolEntry> {
	let spool = FsSpool::open(dir).expect("spool");
	spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| spool.load(id).expect("entry"))
		.collect()
}

#[test]
fn a_forwarded_copy_names_the_forwarding_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	sink(dir.path())
		.deliver(inbound(b"Subject: hi\r\n\r\nbody\r\n"))
		.expect("routed");
	let entries = queued(dir.path());
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].envelope.recipients, ["ext@other.example"]);
	let text = String::from_utf8_lossy(&entries[0].data);
	assert!(
		text.starts_with("Delivered-To: alice@example.org\r\n"),
		"{text}"
	);
	assert!(!text.contains("Return-Path:"), "a relay adds none: {text}");
}

#[test]
fn a_copy_that_comes_back_is_bounced_with_5_4_6_and_not_forwarded() {
	let dir = tempfile::tempdir().expect("tempdir");
	sink(dir.path())
		.deliver(inbound(
			b"Delivered-To: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n",
		))
		.expect("routed");
	let entries = queued(dir.path());
	assert_eq!(entries.len(), 1, "only the bounce");
	let bounce = &entries[0];
	assert_eq!(
		bounce.envelope.reverse_path, "",
		"a DSN has the null sender"
	);
	assert_eq!(bounce.envelope.recipients, ["s@x.example"]);
	let text = String::from_utf8_lossy(&bounce.data);
	assert!(text.contains("Status: 5.4.6"), "{text}");
	assert!(
		text.contains("mail forwarding loop for alice@example.org"),
		"{text}"
	);
}
