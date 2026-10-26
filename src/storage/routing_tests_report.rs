//! A report the server wrote and a mailbox took is not delivered twice
//! because a later step failed, and a recipient that is gone is told apart
//! from a store that is down.

use super::*;
use std::fs;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

fn report_to(recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![recipient.to_string()],
		data: b"Subject: failure\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn inbox_count(root: &std::path::Path) -> usize {
	fs::read_dir(root.join("accounts").join("alice").join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0)
}

#[test]
fn a_later_failure_after_the_mailbox_took_the_report_is_not_returned() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account).expect("mkdir");
	fs::write(
		account.join("filter.sieve"),
		"keep;\nredirect \"forward@example.com\";",
	)
	.expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	// The redirect cannot be queued: the spool is not a directory any more.
	fs::remove_dir_all(dir.path().join("spool")).expect("remove the spool");
	fs::write(dir.path().join("spool"), b"").expect("break the spool");

	let mut report = report_to("alice@example.org");
	report.reverse_path = "mailer@example.net".into();
	let plain = sink.deliver(report.clone());
	assert!(matches!(plain, Err(SinkError::Unavailable(_))), "{plain:?}");
	assert_eq!(inbox_count(dir.path()), 1);

	sink.deliver_report(report)
		.expect("the report is in the mailbox; the failure after it is only logged");
	assert_eq!(inbox_count(dir.path()), 2, "taken once more, never twice");
}

#[test]
fn a_recipient_that_no_longer_exists_is_gone_not_unavailable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let refused = sink.deliver_report(report_to("ghost@example.org"));
	assert!(matches!(refused, Err(SinkError::Gone(_))), "{refused:?}");
}

#[test]
fn a_recipient_that_is_only_switched_off_is_unavailable_not_gone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string(), "off.example".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("carol@off.example".to_string(), "carol".to_string()),
			],
		)
		.with_disabled_domains(["off.example".to_string()])
		.with_masked_paused(["mask.paused@example.org".to_string()]),
	);
	let sink = SplitDelivery::new(dir.path(), directory).expect("sink");
	for recipient in ["carol@off.example", "mask.paused@example.org"] {
		let refused = sink.deliver_report(report_to(recipient));
		assert!(
			matches!(refused, Err(SinkError::Unavailable(_))),
			"{recipient}: {refused:?}"
		);
	}
}
