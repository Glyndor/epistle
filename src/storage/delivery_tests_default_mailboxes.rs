use super::tests::{directory, message};
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
