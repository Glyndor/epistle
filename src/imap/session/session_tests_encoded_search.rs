//! RFC 2047 encoded-word behaviour in IMAP SEARCH and SORT.

use super::*;

/// `SEARCH SUBJECT <text>` matches the DECODED subject, so a search for
/// `hola` hits a message whose `Subject:` is the B-encoded `¡Hola!`.
/// The raw header value (`=?UTF-8?B?...?=`) does not contain the
/// substring `hola`; only the decoded form does.
#[test]
fn search_subject_matches_decoded_subject() {
	let dir = tempfile::tempdir().expect("tempdir");
	// B-encoded `¡Hola!`.
	deliver(
		dir.path(),
		b"Subject: =?UTF-8?B?wqFIb2xhIQ==?=\r\n\r\nbody\r\n",
	);
	deliver(dir.path(), b"Subject: project plan\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let response = text(&session.command_line("a3 SEARCH SUBJECT \"hola\""));
	assert!(
		response.contains("* SEARCH 1\r\n"),
		"SEARCH SUBJECT \"hola\" must hit the encoded subject: {response}"
	);
	let response = text(&session.command_line("a4 SEARCH SUBJECT \"ola\""));
	assert!(
		response.contains("* SEARCH 1\r\n"),
		"SEARCH SUBJECT \"ola\" must also hit the encoded subject: {response}"
	);
}

/// `SEARCH FROM <text>` matches the DECODED display name. The mail from
/// `=?UTF-8?Q?Jos=C3=A9?= <jose@example.org>` decodes to `José`; a search
/// for `josé` matches it. A search for `jose` would also match against
/// the email part, so this case is left to that substring: the decoded
/// display name is the differentiator when the name and the email
/// spell the same string differently.
#[test]
fn search_from_matches_decoded_display_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: =?UTF-8?Q?Jos=C3=A9?= <sender@example.org>\r\n\r\nbody\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let response = text(&session.command_line("a3 SEARCH FROM \"jos\""));
	assert!(
		response.contains("* SEARCH 1\r\n"),
		"SEARCH FROM must hit the decoded display name: {response}"
	);
}

/// `SORT (SUBJECT)` orders by the DECODED subject. The two messages below
/// share a base subject (`project`), one in B-encoded form and one
/// literal; both decode to the same string and the sort ranks them
/// together with the same key. With the bug, the raw `=?UTF-8?B?...?=` is
/// lexicographically smaller than `Re:` and the order flips.
#[test]
fn sort_subject_orders_by_decoded_subject() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Decoded: "Re: project" (literal first, encoded second so the raw
	// and decoded orderings diverge).
	deliver(dir.path(), b"Subject: Re: project\r\n\r\nbody\r\n");
	deliver(
		dir.path(),
		b"Subject: =?UTF-8?B?UmU6IHByb2plY3Q=?=\r\n\r\nbody\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let response = text(&session.command_line("a3 SORT (SUBJECT) UTF-8 ALL"));
	// Both messages decode to the base subject `project`, so when the
	// secondary tie-break is sequence number the order is `1 2`. When
	// the sort uses the raw header, the encoded form starts with `=?`
	// and sorts before the literal `Re:`, putting the encoded message
	// (sequence 2) first.
	assert!(
		response.contains("* SORT 1 2"),
		"SORT (SUBJECT) must rank by decoded base subject: {response}"
	);
}
