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
	deliver(dir.path(), b"From: a@x.example\r\nSubject: one\r\n\r\none\r\n");
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
	deliver(dir.path(), b"From: a@x.example\r\nSubject: existing\r\n\r\nexisting\r\n");
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
