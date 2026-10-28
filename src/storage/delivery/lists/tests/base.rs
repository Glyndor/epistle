
use super::*;

fn block(id: &str) -> ListBlock {
	ListBlock {
		identity: format!("List-Id: <{id}>\r\n"),
		unsubscribe: None,
	}
}

fn message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["team@example.org".into()],
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: true,
		mailbox: Some("Lists".into()),
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: vec!["bob@example.org".into()],
	}
}

/// Every member of one list is handed the same built copy, so a list of a
/// thousand members copies the body once and not a thousand times; a
/// second list gets its own, and a delivery through no list gets the
/// message itself.
#[test]
fn a_list_is_built_once_however_many_members_it_has() {
	let message = message();
	let mut copies = ListedCopies::new(&message);
	for _ in 0..3 {
		copies.for_list(Some(&block("a")));
	}
	assert_eq!(copies.builds, 1, "the same list must reuse its copy");
	let other = copies.for_list(Some(&block("b")));
	assert!(other.data.starts_with(b"List-Id: <b>\r\n"));
	assert_eq!(copies.builds, 2, "a second list gets its own copy");
	let plain = copies.for_list(None);
	assert!(
		std::ptr::eq(plain, &message),
		"no list: the message as it came"
	);
}

/// The listed copy is the message with the headers in front and nothing
/// else changed.
#[test]
fn a_listed_copy_keeps_every_other_field() {
	let message = message();
	let copy = listed_message(&message, &block("a"));
	assert_eq!(copy.data, b"List-Id: <a>\r\nSubject: hi\r\n\r\nbody\r\n");
	assert_eq!(copy.reverse_path, message.reverse_path);
	assert_eq!(copy.recipients, message.recipients);
	assert_eq!(copy.mailbox, message.mailbox);
	assert_eq!(copy.no_dsn, message.no_dsn);
	assert!(copy.require_tls && copy.sender_verified && !copy.tlsrpt_verified);
}
