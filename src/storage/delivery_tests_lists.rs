//! The list identity of a delivered copy. The `List-*` headers belong to the
//! list the delivery went through, so two lists in one envelope keep their
//! own identity and a recipient addressed directly takes none.

use super::*;
use crate::smtp::directory::AliasSpec;

/// `team` reaches alice and bob, `announce` reaches carol. Both are lists.
fn directory_with_lists() -> DirectoryHandle {
	DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
				("carol@example.org".to_string(), "carol".to_string()),
			],
		)
		.with_aliases([
			(
				"team@example.org".to_string(),
				AliasSpec {
					members: vec![
						"alice@example.org".to_string(),
						"bob@example.org".to_string(),
					],
					senders: Vec::new(),
					hidden: true,
					list_id: Some("team.example.org".to_string()),
				},
			),
			(
				"announce@example.org".to_string(),
				AliasSpec {
					members: vec!["carol@example.org".to_string()],
					senders: Vec::new(),
					hidden: true,
					list_id: Some("announce.example.org".to_string()),
				},
			),
		]),
	)
}

fn message_to(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// The copy delivered to `account`, read from its INBOX.
fn copy(root: &std::path::Path, account: &str) -> String {
	let files: Vec<PathBuf> = fs::read_dir(root.join("accounts").join(account).join("new"))
		.expect("inbox")
		.map(|entry| entry.expect("entry").path())
		.collect();
	assert_eq!(files.len(), 1, "one copy for {account}");
	fs::read_to_string(&files[0]).expect("read the copy")
}

#[test]
fn each_list_keeps_its_own_identity() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory_with_lists()).expect("delivery");
	delivery
		.deliver_routed(
			&message_to(&["team@example.org", "announce@example.org"]),
			None,
		)
		.expect("deliver");

	let alice = copy(dir.path(), "alice");
	assert!(alice.contains("List-Id: <team.example.org>"), "{alice}");
	assert!(!alice.contains("announce.example.org"), "{alice}");
	let bob = copy(dir.path(), "bob");
	assert!(bob.contains("List-Id: <team.example.org>"), "{bob}");
	assert!(!bob.contains("announce.example.org"), "{bob}");
	let carol = copy(dir.path(), "carol");
	assert!(carol.contains("List-Id: <announce.example.org>"), "{carol}");
	assert!(!carol.contains("team.example.org"), "{carol}");
}

#[test]
fn a_recipient_addressed_directly_takes_no_list_identity() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory_with_lists()).expect("delivery");
	delivery
		.deliver_routed(
			&message_to(&["team@example.org", "carol@example.org"]),
			None,
		)
		.expect("deliver");

	let alice = copy(dir.path(), "alice");
	assert!(alice.contains("List-Id: <team.example.org>"), "{alice}");
	// Carol was addressed directly, so her copy is the message as it came.
	let carol = copy(dir.path(), "carol");
	assert!(!carol.contains("List-Id"), "{carol}");
	assert!(!carol.contains("List-Unsubscribe"), "{carol}");
}

#[test]
fn a_member_addressed_directly_keeps_the_plain_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory_with_lists()).expect("delivery");
	delivery
		.deliver_routed(&message_to(&["team@example.org", "bob@example.org"]), None)
		.expect("deliver");

	// Bob is a member of the list and was also addressed directly: the
	// copy he receives is his own mail, not a post of the list.
	let bob = copy(dir.path(), "bob");
	assert!(!bob.contains("List-Id"), "{bob}");
	let alice = copy(dir.path(), "alice");
	assert!(alice.contains("List-Id: <team.example.org>"), "{alice}");
}
