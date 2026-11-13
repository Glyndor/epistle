use super::*;

/// RFC 3501 7.2.6 / RFC 9051 7.3.5: when STORE or APPEND introduces a new
/// keyword, the server must send an updated untagged `FLAGS` response
/// (with the new keyword present) before the FETCH that mentions it.
/// Clients like Dovecot's imaptest track the per-mailbox keyword set
/// from the most recent FLAGS response and bail out with
/// `Keyword used without being in FLAGS: $hello` when a FETCH carries
/// a keyword they have not seen advertised yet.
#[test]
fn store_introducing_keyword_emits_updated_flags() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: a@x.example\r\nSubject: one\r\n\r\none\r\n",
	);
	let mut session = logged_in(dir.path());
	let select = text(&session.command_line("a1 SELECT INBOX"));
	assert!(select.contains("a1 OK"), "{select}");
	// Initial mailbox has no user keywords in use; the FLAGS list omits them.
	assert!(
		select.contains("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n"),
		"initial SELECT must list the five system flags with no keywords: {select}"
	);

	let store = text(&session.command_line("a2 STORE 1 +FLAGS ($hello)"));
	// The first response line for any message STORE touches must be the
	// updated untagged FLAGS response, so the new keyword $hello is
	// declared before it appears inside a FETCH.
	let flags_idx = store
		.find("* FLAGS (")
		.expect("STORE introducing $hello must send an untagged FLAGS response");
	let fetch_idx = store
		.find("* 1 FETCH (FLAGS ($hello))")
		.expect("STORE introducing $hello must reflect the keyword on the affected message");
	assert!(
		flags_idx < fetch_idx,
		"updated FLAGS must precede the FETCH that carries the keyword; got reply:\n{store}"
	);
	let flags_end = store[flags_idx..]
		.find("\r\n")
		.map(|offset| flags_idx + offset)
		.expect("FLAGS line must end");
	let flags_line = store[flags_idx..flags_end].to_string();
	assert!(
		flags_line.contains("$hello"),
		"updated FLAGS must list $hello in use, saw: {flags_line}"
	);
	assert!(
		store.contains("a2 OK"),
		"STORE must still produce a tagged OK completion: {store}"
	);
}

/// Symmetric guarantee for APPEND: the literal data may carry a keyword
/// (RFC 9051 6.3.1 flags list inside the APPEND command). A subsequent
/// SELECT must advertise the keyword so a client that has not been
/// observing the mailbox does not see it for the first time past the
/// tagged completion.
#[test]
fn append_introducing_keyword_advertises_it_on_next_select() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: a@x.example\r\nSubject: existing\r\n\r\nexisting\r\n",
	);
	let mut session = logged_in(dir.path());
	let select = text(&session.command_line("a1 SELECT INBOX"));
	assert!(select.contains("a1 OK"), "{select}");

	let output = session.command_line("a2 APPEND INBOX ($greet) {19}");
	assert_eq!(output.collect_literal, Some(19));
	assert!(text(&output).starts_with("+ "));
	let output = session.literal_done(b"Subject: appended\r\n\r\nhi\r\n");
	let response = text(&output);
	assert!(response.contains("a2 OK"), "{response}");
	assert!(response.contains("[APPENDUID "), "{response}");

	// Re-select INBOX: the new keyword the APPEND applied must now be
	// advertised in the FLAGS response.
	let reselect = text(&session.command_line("a3 SELECT INBOX"));
	assert!(reselect.contains("a3 OK"), "{reselect}");
	assert!(
		reselect.contains("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft $greet)\r\n"),
		"a fresh SELECT must advertise $greet as in use, saw: {reselect}"
	);
}

fn put(dir: &std::path::Path, id: &str, body: &[u8]) {
	let new_dir = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&new_dir).expect("create dirs");
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
}

const A: &str = "00000000-0000-7000-8000-000000000002";
const B: &str = "00000000-0000-7000-8000-000000000003";
/// Sorts before both: a message that enters the mailbox after them although
/// its file name is the lowest.
const LATE: &str = "00000000-0000-7000-8000-000000000001";

#[test]
fn a_message_with_a_low_file_name_arriving_late_is_numbered_last() {
	let dir = tempfile::tempdir().expect("tempdir");
	put(dir.path(), A, b"Subject: a\r\n\r\na\r\n");
	put(dir.path(), B, b"Subject: b\r\n\r\nb\r\n");
	let mut session = logged_in(dir.path());
	let select = text(&session.command_line("a1 SELECT INBOX"));
	assert!(select.contains("a1 OK"), "{select}");
	// Another session sets \Seen on B, and a message arrives whose file name
	// sorts before A and B.
	let new_dir = dir.path().join("accounts/alice/new");
	std::fs::write(new_dir.join(format!("{B}.flags")), b"[\"seen\"]").expect("flags");
	put(dir.path(), LATE, b"Subject: late\r\n\r\nlate\r\n");

	let noop = text(&session.command_line("a2 NOOP"));
	assert!(noop.contains("* 2 FETCH (FLAGS (\\Seen))\r\n"), "{noop}");
	assert!(noop.contains("* 3 EXISTS\r\n"), "{noop}");
	// What the client was told must be what the server numbers: the late
	// message is number 3 and B is still number 2.
	let fetch = text(&session.command_line("a3 FETCH 1:* (UID)"));
	assert!(
		fetch.contains("* 1 FETCH (UID 1)\r\n")
			&& fetch.contains("* 2 FETCH (UID 2)\r\n")
			&& fetch.contains("* 3 FETCH (UID 3)\r\n"),
		"the sequence numbers must follow the UIDs: {fetch}"
	);
}
