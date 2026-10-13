use super::*;

/// RFC 9051 §7.1.2 + §7.4: NOOP is the client's poll primitive. When the
/// SELECTed mailbox's count changed since the last untagged response, the
/// server must announce the new value via `* N EXISTS` before the tagged
/// OK. Dovecot's imaptest strictly checks `* N EXISTS` on every reply
/// that could carry a state delta; a server that only re-announces when
/// the count differs from the last announcement wins by just `Missing N
/// untagged replies` after every APPEND followed by NOOP.
#[test]
fn noop_emits_untagged_exists_after_unannounced_arrival() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let select = text(&session.command_line("a1 SELECT INBOX"));
	assert!(select.contains("a1 OK"), "{select}");

	// Append while selected so the snapshot already has the new message
	// but the client has only seen the SELECT announcement.
	let output = session.command_line("a2 APPEND INBOX {19}");
	assert!(text(&output).starts_with("+ "));
	let append = text(&session.literal_done(b"Subject: hi\r\n\r\nhi\r\n"));
	assert!(append.contains("a2 OK"), "{append}");
	let exists_after_append: u32 = append
		.lines()
		.find_map(|line| {
			line.strip_prefix("* ")
				.and_then(|rest| rest.strip_suffix(" EXISTS").and_then(|n| n.parse().ok()))
		})
		.expect("APPEND must announce the new message count via untagged EXISTS");

	// A NOOP right after the APPEND must not repeat the count: the
	// client just heard it in the APPEND reply.
	let noop_idle = text(&session.command_line("a3 NOOP"));
	assert!(
		!noop_idle.contains(&format!("* {exists_after_append} EXISTS\r\n")),
		"NOOP right after APPEND must not re-announce the count the client just heard; saw: {noop_idle}"
	);
	assert!(noop_idle.contains("a3 OK"), "{noop_idle}");

	// A second APPEND bumps the count. The reply re-announces, so a
	// subsequent NOOP stays silent.
	let output = session.command_line("a4 APPEND INBOX {19}");
	assert!(text(&output).starts_with("+ "));
	let second = text(&session.literal_done(b"Subject: hi2\r\n\r\nhi\r\n"));
	assert!(second.contains("a4 OK"), "{second}");
	let final_count = exists_after_append + 1;
	let noop = text(&session.command_line("a5 NOOP"));
	assert!(
		!noop.contains(&format!("* {final_count} EXISTS\r\n")),
		"NOOP right after the second APPEND must not re-announce the count the APPEND reply just delivered; saw: {noop}"
	);
	assert!(noop.contains("a5 OK"), "{noop}");
}

/// RFC 9051 §7.4: when the SELECTed mailbox's count changed between two
/// commands (the gap in which no reply was in flight), the next command
/// that returns a reply must re-announce via `* N EXISTS`. Dovecot's
/// imaptest verifies the EXACT exchange on every scripted test that
/// observes a NOOP after an external arrival.
#[test]
fn noop_emits_exists_when_count_changed_since_last_announcement() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: a@x.example\r\nSubject: seed\r\n\r\nseed\r\n",
	);
	let mut session = logged_in(dir.path());
	let select = text(&session.command_line("a1 SELECT INBOX"));
	assert!(select.contains("a1 OK"), "{select}");
	let initial_count: u32 = select
		.lines()
		.find_map(|line| {
			line.strip_prefix("* ")
				.and_then(|rest| rest.strip_suffix(" EXISTS").and_then(|n| n.parse().ok()))
		})
		.expect("SELECT must announce the message count");

	// Deliver a second message out-of-band by writing the file directly,
	// the same way the SMTP path does. The session has no idea until
	// the next NOOP refreshes the snapshot.
	deliver(
		dir.path(),
		b"From: a@x.example\r\nSubject: late\r\n\r\nlate\r\n",
	);

	// NOOP must observe the new file and announce the new count.
	let noop = text(&session.command_line("a2 NOOP"));
	let expected = format!("* {} EXISTS\r\n", initial_count + 1);
	assert!(
		noop.contains(&expected),
		"NOOP must re-announce when the count drifted since SELECT; expected {expected:?}, saw: {noop}"
	);
	assert!(noop.contains("a2 OK"), "{noop}");
}
