//! STATUS, LIST, SUBSCRIBE and INTERNALDATE over a session.

use super::*;
#[test]
fn status_reports_counts_for_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());

	let response =
		text(&session.command_line("a2 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN RECENT)"));
	assert!(response.contains("MESSAGES 2"), "{response}");
	assert!(response.contains("UNSEEN 2"), "{response}");
	assert!(response.contains("RECENT 0"), "{response}");
	assert!(response.contains("a2 OK STATUS completed"), "{response}");

	// Mark one seen; UNSEEN should drop to 1.
	session.command_line("a3 SELECT INBOX");
	session.command_line(r"a4 STORE 1 +FLAGS (\Seen)");
	session.command_line("a5 CLOSE");
	let response = text(&session.command_line("a6 STATUS INBOX (MESSAGES UNSEEN)"));
	assert!(response.contains("MESSAGES 2"), "{response}");
	assert!(response.contains("UNSEEN 1"), "{response}");
}

#[test]
fn list_status_reports_counts_inline() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	let response =
		text(&session.command_line("a2 LIST \"\" \"*\" RETURN (STATUS (MESSAGES UNSEEN))"));
	assert!(response.contains("* LIST"), "{response}");
	assert!(
		response.contains("* STATUS \"INBOX\" (MESSAGES 1 UNSEEN 1)"),
		"{response}"
	);
	assert!(response.contains("a2 OK LIST completed"), "{response}");
	// Capability advertises LIST-STATUS.
	assert!(
		text(&session.command_line("a3 CAPABILITY")).contains("LIST-STATUS"),
		"capability should advertise LIST-STATUS"
	);
}

#[test]
fn status_reports_size() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"hello\r\n");
	deliver(dir.path(), b"world!\r\n");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 STATUS INBOX (SIZE)"));
	// "hello\r\n" (7) + "world!\r\n" (8) = 15 octets.
	assert!(response.contains("SIZE 15"), "{response}");
	assert!(response.contains("a2 OK STATUS completed"), "{response}");
}

#[test]
fn status_requires_authentication_and_existing_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 STATUS INBOX (MESSAGES)");
	assert!(text(&output).contains("a1 NO"), "{}", text(&output));

	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 STATUS Missing (MESSAGES)");
	assert!(text(&output).contains("a2 NO"), "{}", text(&output));
}

#[test]
fn subscribe_and_lsub_flow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Sent");

	// INBOX always present in LSUB even without explicit SUBSCRIBE.
	let response = text(&session.command_line(r#"a3 LSUB "" "*""#));
	assert!(response.contains("\"INBOX\""), "{response}");
	assert!(response.contains("a3 OK LSUB completed"), "{response}");

	// Subscribe Sent; it must appear.
	let output = session.command_line("a4 SUBSCRIBE Sent");
	assert!(text(&output).contains("a4 OK"), "{}", text(&output));
	let response = text(&session.command_line(r#"a5 LSUB "" "*""#));
	assert!(response.contains("\"Sent\""), "{response}");

	// Unsubscribe Sent; it disappears.
	session.command_line("a6 UNSUBSCRIBE Sent");
	let response = text(&session.command_line(r#"a7 LSUB "" "*""#));
	assert!(!response.contains("\"Sent\""), "{response}");
	assert!(response.contains("\"INBOX\""), "{response}");
}

#[test]
fn list_extended_subscribed_selection_and_attribute() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("rev ENABLE IMAP4rev2");
	session.command_line("a2 CREATE Sent");
	session.command_line("a3 SUBSCRIBE Sent");

	// Plain LIST annotates subscribed mailboxes with \Subscribed (Sent also
	// carries its \Sent special-use attribute).
	let response = text(&session.command_line(r#"a4 LIST "" "*""#));
	assert!(
		response
			.lines()
			.any(|l| l.contains("\"Sent\"") && l.contains("\\Subscribed")),
		"{response}"
	);

	// (SUBSCRIBED) lists only subscribed mailboxes (not the unsubscribed one).
	session.command_line("a5 CREATE Work");
	let response = text(&session.command_line(r#"a6 LIST (SUBSCRIBED) "" "*""#));
	assert!(response.contains("\"Sent\""), "{response}");
	assert!(!response.contains("\"Work\""), "{response}");
	assert!(response.contains("a6 OK LIST completed"), "{response}");
}

#[test]
fn list_advertises_has_no_children() {
	// CHILDREN (RFC 3348): every LIST line carries \HasNoChildren or
	// \HasChildren. None of these mailboxes has a folder under it, so each
	// is \HasNoChildren; list_status/hierarchy covers \HasChildren.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("rev ENABLE IMAP4rev2");
	session.command_line("a2 CREATE Sent");
	session.command_line("a3 CREATE Work");

	let response = text(&session.command_line(r#"a4 LIST "" "*""#));
	let list_lines: Vec<&str> = response
		.lines()
		.filter(|l| l.starts_with("* LIST "))
		.collect();
	assert!(
		list_lines.len() >= 3,
		"expected at least INBOX + Sent + Work, got {list_lines:?}"
	);
	for line in &list_lines {
		assert!(
			line.contains("\\HasNoChildren"),
			"missing \\HasNoChildren in: {line}"
		);
		assert!(
			!line.contains("\\HasChildren"),
			"unexpected \\HasChildren on a leaf: {line}"
		);
	}

	// CHILDREN advertised only when the rest of the test passes.
	assert!(
		text(&session.command_line("a5 CAPABILITY")).contains("CHILDREN"),
		"capability should advertise CHILDREN"
	);
}

#[test]
fn list_children_selection_option_is_accepted() {
	// RFC 3348 §3.3 lets the client request child expansion with the
	// `(CHILDREN)` selection option. It selects nothing more; these leaves
	// are all marked \HasNoChildren.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Sent");

	let response = text(&session.command_line(r#"a3 LIST (CHILDREN) "" "*""#));
	assert!(response.contains("\"INBOX\""), "{response}");
	assert!(response.contains("\"Sent\""), "{response}");
	assert!(
		response.contains("\\HasNoChildren"),
		"expected child attribute in {response}"
	);
	assert!(response.contains("a3 OK LIST completed"), "{response}");

	// Unknown selection options are rejected with BAD.
	let response = text(&session.command_line(r#"a4 LIST (BOGUS) "" "*""#));
	assert!(response.contains("a4 BAD"), "{response}");
}

#[test]
fn internaldate_is_not_epoch() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\nhi\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 FETCH 1 (INTERNALDATE)"));
	// Must not be the epoch placeholder.
	assert!(!response.contains("01-Jan-1970"), "{response}");
	assert!(response.contains("INTERNALDATE"), "{response}");
	assert!(response.contains("a3 OK FETCH completed"), "{response}");
}

#[test]
fn internaldate_format_sanity() {
	// 2024-06-09 12:34:56 UTC = 1717936496 seconds since epoch.
	let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_717_936_496);
	assert_eq!(format_internaldate(t), " 9-Jun-2024 12:34:56 +0000");
	// Epoch itself.
	assert_eq!(
		format_internaldate(std::time::UNIX_EPOCH),
		" 1-Jan-1970 00:00:00 +0000"
	);
	// A date with a two-digit day (no space padding).
	let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_718_000_000);
	let s = format_internaldate(t);
	// 2024-06-10 in UTC; day >= 10 so no leading space.
	assert!(
		!s.starts_with(' '),
		"expected no leading space for day >= 10: {s}"
	);
}
