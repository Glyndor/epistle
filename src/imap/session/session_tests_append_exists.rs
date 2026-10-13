use super::*;

/// RFC 9051 §7.4: a successful APPEND on a SELECTed mailbox must
/// announce the new message count before the tagged completion. Clients
/// that track `EXISTS` (and Dovecot's imaptest in particular) rely on
/// the untagged line to keep their view of the mailbox consistent; a
/// server that only emits the tagged OK leaves them out of sync and
/// surfaces as `Missing N untagged replies` in the scripted suite.
#[test]
fn append_emits_untagged_exists_for_selected_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let select = text(&session.command_line("a1 SELECT INBOX"));
	assert!(select.contains("a1 OK"), "{select}");
	let initial_exists: u32 = select
		.lines()
		.find_map(|line| {
			line.strip_prefix("* ")
				.and_then(|rest| rest.strip_suffix(" EXISTS").and_then(|n| n.parse().ok()))
		})
		.expect("SELECT must announce the message count");

	let output = session.command_line("a2 APPEND INBOX {19}");
	assert!(text(&output).starts_with("+ "));
	let response = text(&session.literal_done(b"Subject: hi\r\n\r\nhi\r\n"));
	let expected = format!("* {} EXISTS\r\n", initial_exists + 1);
	assert!(
		response.contains(&expected),
		"APPEND to a SELECTed mailbox must announce the new message count via untagged EXISTS before the tagged completion; expected {expected:?}, saw: {response}"
	);
	assert!(response.contains("a2 OK"), "{response}");
}