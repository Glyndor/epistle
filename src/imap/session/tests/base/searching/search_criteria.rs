//! SEARCH criteria: flags, headers, dates, sizes and age.

use super::*;

#[test]
fn search_by_flags_headers_and_text() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: alice@example.org\r\nSubject: project update\r\n\r\nquarterly numbers\r\n",
	);
	deliver(
		dir.path(),
		b"From: bob@example.org\r\nSubject: lunch\r\n\r\ntacos tomorrow\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");

	let response = text(&session.command_line("a4 SEARCH UNSEEN"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	let response = text(&session.command_line("a5 SEARCH FROM alice"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	let response = text(&session.command_line(r#"a6 SEARCH SUBJECT "project update""#));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	let response = text(&session.command_line("a7 SEARCH TEXT tacos"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// AND semantics: seen + from alice = 1; unseen + from alice = none.
	let response = text(&session.command_line("a8 SEARCH SEEN FROM alice"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");
	let response = text(&session.command_line("a9 SEARCH UNSEEN FROM alice"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");

	let response = text(&session.command_line("b1 SEARCH ALL"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");
}

#[test]
fn search_by_generic_header_and_cc() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: a@x.example\r\nCc: team@x.example\r\nMessage-ID: <abc@x>\r\n\r\nbody\r\n",
	);
	deliver(dir.path(), b"From: b@y.example\r\n\r\nother\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// Generic HEADER search on an arbitrary field.
	let response = text(&session.command_line("a3 SEARCH HEADER Message-ID abc"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// CC is now a recognized header search key.
	let response = text(&session.command_line("a4 SEARCH CC team"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// A header miss returns nothing.
	let response = text(&session.command_line("a5 SEARCH HEADER Message-ID nope"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");
}

#[test]
fn uid_search_returns_uids() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\none\r\n");
	deliver(dir.path(), b"From: a@x.example\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)");
	session.command_line("a4 EXPUNGE");

	// One message left: sequence 1, but UID 2.
	let response = text(&session.command_line("a5 UID SEARCH ALL"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");
	let response = text(&session.command_line("a6 SEARCH UID 2"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");
}

#[test]
fn search_requires_selection_and_valid_criteria() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 SEARCH ALL"));
	assert!(response.contains("a2 BAD"), "{response}");
	session.command_line("a3 SELECT INBOX");
	let response = text(&session.command_line("a4 SEARCH BOGUSKEY"));
	assert!(response.contains("a4 BAD"), "{response}");
}

#[test]
fn search_or_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\none\r\n");
	deliver(dir.path(), b"From: b@example.org\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");

	// OR SEEN FLAGGED → message 1 (seen) only
	let response = text(&session.command_line("a4 SEARCH OR SEEN FLAGGED"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// OR SEEN UNSEEN → all
	let response = text(&session.command_line("a5 SEARCH OR SEEN UNSEEN"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");

	// NOT SEEN → message 2
	let response = text(&session.command_line("a6 SEARCH NOT SEEN"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// Nested: OR (NOT SEEN) FLAGGED → message 2
	let response = text(&session.command_line("a7 SEARCH OR (NOT SEEN) FLAGGED"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");
}

#[test]
fn search_date_criteria() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// SINCE epoch: all messages match (files exist after 1970).
	let response = text(&session.command_line("a3 SEARCH SINCE 1-Jan-1970"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// BEFORE far future: all messages match.
	let response = text(&session.command_line("a4 SEARCH BEFORE 1-Jan-2200"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// SINCE far future: no messages match.
	let response = text(&session.command_line("a5 SEARCH SINCE 1-Jan-2200"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");

	// BEFORE epoch: no messages match (files are newer than 1970-01-01).
	let response = text(&session.command_line("a6 SEARCH BEFORE 1-Jan-1970"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");
}

#[test]
fn search_larger_smaller() {
	let dir = tempfile::tempdir().expect("tempdir");
	let short = b"From: a@example.org\r\n\r\nhi\r\n";
	let long = b"From: b@example.org\r\n\r\nThis is a much longer message body.\r\n";
	deliver(dir.path(), short);
	deliver(dir.path(), long);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// LARGER 5 → both messages (both > 5 bytes).
	let response = text(&session.command_line("a3 SEARCH LARGER 5"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");

	// LARGER 50 → only the long message (60 bytes > 50; short is 27 bytes).
	let response = text(&session.command_line("a4 SEARCH LARGER 50"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// SMALLER 50 → only the short message (27 bytes < 50; long is 60 bytes).
	let response = text(&session.command_line("a5 SEARCH SMALLER 50"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// SMALLER 5 → no messages (both > 5 bytes).
	let response = text(&session.command_line("a6 SEARCH SMALLER 5"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");
}

/// Backdate every `.eml` in alice's inbox to `secs_ago` seconds before now, so
/// WITHIN search tests are deterministic without sleeps.
pub(super) fn backdate_inbox(dir: &std::path::Path, secs_ago: u64) {
	let new_dir = dir.join("accounts").join("alice").join("new");
	let target = std::time::SystemTime::now() - std::time::Duration::from_secs(secs_ago);
	for entry in std::fs::read_dir(&new_dir).expect("read new").flatten() {
		let Ok(file) = std::fs::OpenOptions::new().write(true).open(entry.path()) else {
			continue;
		};
		let _ = file.set_modified(target);
	}
}

#[test]
fn search_younger_older_filters_by_internal_age() {
	// WITHIN (RFC 5032): YOUNGER n matches messages whose internal date is
	// within the last n seconds; OLDER n matches older than n seconds.
	// Backdate both messages to 10 seconds ago so the bounds are deterministic.
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\nolder\r\n");
	deliver(dir.path(), b"From: b@example.org\r\n\r\nalso-older\r\n");
	backdate_inbox(dir.path(), 10);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// YOUNGER 5 → no match (both messages are 10s old).
	let response = text(&session.command_line("a3 SEARCH YOUNGER 5"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");

	// YOUNGER 60 → both match (10s < 60s).
	let response = text(&session.command_line("a4 SEARCH YOUNGER 60"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");

	// OLDER 5 → both match (10s > 5s).
	let response = text(&session.command_line("a5 SEARCH OLDER 5"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");

	// OLDER 60 → no match (10s < 60s).
	let response = text(&session.command_line("a6 SEARCH OLDER 60"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");

	// Malformed argument is rejected (negative or non-numeric).
	let response = text(&session.command_line("a7 SEARCH YOUNGER"));
	assert!(response.contains("a7 BAD"), "{response}");

	// Capability advertises WITHIN.
	assert!(
		text(&session.command_line("a8 CAPABILITY")).contains("WITHIN"),
		"capability should advertise WITHIN"
	);
}

/// Deliver a message straight into a non-INBOX mailbox's `new` directory.
pub(super) fn deliver_to(dir: &std::path::Path, mailbox: &str, body: &[u8]) {
	let new_dir = dir
		.join("accounts")
		.join("alice")
		.join("folders")
		.join(mailbox)
		.join("new");
	std::fs::create_dir_all(&new_dir).expect("create dirs");
	let id = uuid::Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
}
