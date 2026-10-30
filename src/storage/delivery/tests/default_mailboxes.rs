use super::base::{directory, message};
use super::*;

#[test]
fn default_mailboxes_first_delivery_initializes_inbox_and_special_use_folders() {
	for target in [None, Some("Rejects")] {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = LocalDelivery::new(dir.path(), directory()).expect("delivery");
		sink.deliver_routed(&message(&["alice@example.org"]), target)
			.expect("deliver");
		assert!(
			crate::imap::mailbox::list(dir.path(), "alice")
				== ["INBOX", "Archive", "Drafts", "Rejects", "Sent", "Trash"],
			"first delivery must create INBOX and five special-use folders"
		);
		assert!(
			dir.path().join("accounts/alice/new").is_dir(),
			"first routed delivery must also create INBOX storage"
		);
	}
}

/// An SMTP delivery is recorded for JMAP, together with the default
/// mailboxes it creates and the folder a Sieve `fileinto` creates.
#[test]
fn delivery_records_its_changes_for_jmap() {
	use crate::imap::changelog::{Change, Object, Op};
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	sink.deliver_routed(&message(&["alice@example.org"]), Some("Lists"))
		.expect("deliver");
	let root = dir.path().join("accounts").join("alice");
	let epoch = crate::imap::changelog::current(&root)
		.expect("current")
		.epoch;
	let (_, entries) = crate::imap::changelog::since(&root, epoch, 0).expect("since");
	let changes: Vec<Change> = entries.into_iter().map(|e| e.change).collect();
	let created_mailboxes: Vec<&str> = changes
		.iter()
		.filter(|c| c.object == Object::Mailbox && c.op == Op::Created)
		.map(|c| c.id.as_str())
		.collect();
	assert_eq!(
		created_mailboxes,
		["Rejects", "Sent", "Drafts", "Trash", "Archive", "Lists"]
	);
	let emails: Vec<&Change> = changes
		.iter()
		.filter(|c| c.object == Object::Email)
		.collect();
	assert_eq!(emails.len(), 1, "{changes:?}");
	assert_eq!(emails[0].op, Op::Created);
	assert_eq!(
		changes.last(),
		Some(&Change::mailbox(Op::Updated, "Lists")),
		"the receiving mailbox's counts changed"
	);
}
