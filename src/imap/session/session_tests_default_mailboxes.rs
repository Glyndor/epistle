use super::*;

fn expected_list(rev2: bool, special_use: bool) -> String {
	let mut response = String::new();
	for (name, role) in [
		("INBOX", ""),
		("Archive", "\\Archive"),
		("Drafts", "\\Drafts"),
		("Rejects", "\\Junk"),
		("Sent", "\\Sent"),
		("Trash", "\\Trash"),
	] {
		let mut attrs = if rev2 || special_use { role } else { "" }.to_string();
		if rev2 {
			if name == "INBOX" {
				attrs.push_str("\\Subscribed");
			}
			if !attrs.is_empty() {
				attrs.push(' ');
			}
			attrs.push_str("\\HasNoChildren");
		}
		response.push_str(&format!("* LIST ({attrs}) \"/\" \"{name}\"\r\n"));
	}
	response.push_str("l OK LIST completed\r\n");
	response
}

#[test]
fn default_mailboxes_fresh_login_lists_roles_and_second_login_is_idempotent() {
	let dir = tempfile::tempdir().expect("tempdir");
	for _ in 0..2 {
		let mut session = logged_in(dir.path());
		for (command, rev2, special_use) in [
			(r#"l LIST "" "*" RETURN (SPECIAL-USE)"#, false, true),
			(r#"l LIST "" "*""#, false, false),
			(r#"l LIST "" "*""#, true, false),
		] {
			if rev2 {
				session.command_line("e ENABLE IMAP4rev2");
			}
			assert!(
				text(&session.command_line(command)) == expected_list(rev2, special_use),
				"default mailboxes must list INBOX and five special-use folders exactly once"
			);
		}
	}
}

#[test]
fn default_mailboxes_existing_sent_preserves_messages_metadata_and_subscription() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: inbox\r\n\r\nbody\r\n");
	mailbox::create(dir.path(), "alice", "Sent").expect("create Sent");
	mailbox::create(dir.path(), "alice", "Rejects").expect("create Rejects");
	let crypto = crate::storage::MessageCrypto::disabled();
	let id = mailbox::append(
		dir.path(),
		"alice",
		"Sent",
		&[mailbox::Flag::Seen],
		b"Subject: sent\r\n\r\nbody\r\n",
		&crypto,
	)
	.expect("append Sent");
	mailbox::subscribe(dir.path(), "alice", "Sent").expect("subscribe");
	let before = mailbox::Snapshot::open(dir.path(), "alice", "Sent", &crypto).expect("snapshot");
	for _ in 0..2 {
		let mut session = logged_in(dir.path());
		assert!(
			text(&session.command_line(r#"l LIST "" "*" RETURN (SPECIAL-USE)"#))
				== expected_list(false, true),
			"existing accounts must gain missing defaults without duplicating Sent"
		);
		let after =
			mailbox::Snapshot::open(dir.path(), "alice", "Sent", &crypto).expect("snapshot");
		assert_eq!(
			after.uid_validity(),
			before.uid_validity(),
			"Sent UIDVALIDITY must be preserved"
		);
		assert_eq!(
			after.uid_next(),
			before.uid_next(),
			"Sent UIDNEXT must be preserved"
		);
		let messages: Vec<_> = after
			.messages()
			.map(|m| (m.id(), m.uid, m.flags.clone()))
			.collect();
		assert!(
			messages == vec![(id, 1, vec![mailbox::Flag::Seen])],
			"Sent message identity and flags must be preserved"
		);
		assert_eq!(
			mailbox::list_subscribed(dir.path(), "alice"),
			vec!["INBOX", "Sent"]
		);
	}
}

#[test]
fn default_mailboxes_sasl_plain_login_initializes_the_store() {
	use base64::Engine;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let credentials = base64::engine::general_purpose::STANDARD.encode(b"\0alice\0secret");
	let output = session.command_line(&format!("a AUTHENTICATE PLAIN {credentials}"));
	assert!(
		text(&output) == "a OK AUTHENTICATE completed\r\n",
		"PLAIN authentication must succeed"
	);
	assert!(
		text(&session.command_line(r#"l LIST "" "*" RETURN (SPECIAL-USE)"#))
			== expected_list(false, true),
		"SASL login must initialize the same default mailboxes as LOGIN"
	);
}
