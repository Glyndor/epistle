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

/// The accented name must match only after decoding, with a nonmatching
/// sender alongside it to rule out unconditional acceptance.
#[test]
fn search_from_matches_decoded_display_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: =?UTF-8?Q?Jos=C3=A9?= <sender@example.org>\r\n\r\nbody\r\n",
	);
	deliver(
		dir.path(),
		b"From: Other <other@example.org>\r\n\r\nbody\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let response = text(&session.command_line("a3 SEARCH FROM \"josé\""));
	assert!(
		response.contains("* SEARCH 1\r\n"),
		"SEARCH FROM must hit the decoded display name: {response}"
	);
	let response = text(&session.command_line("a4 SEARCH FROM \"josè\""));
	assert!(
		response.contains("* SEARCH\r\n"),
		"different accented name must not match: {response}"
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

#[test]
fn search_finds_folded_subject_continuation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let subject = format!("{}tailneedle", "é".repeat(30));
	let encoded = crate::util::encoded_word::encode(&subject);
	deliver(
		dir.path(),
		format!("Subject: {encoded}\r\n\r\nbody\r\n").as_bytes(),
	);
	deliver(dir.path(), b"Subject: other\r\n\r\ntailneedle\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 SEARCH SUBJECT tailneedle"));
	assert!(
		response.contains("* SEARCH 1\r\n"),
		"folded subject search missed continuation: {response}"
	);
}

#[test]
fn sort_uses_folded_subject_continuation() {
	let dir = tempfile::tempdir().expect("tempdir");
	for suffix in ["z", "a"] {
		let subject = format!("{}{}", "é".repeat(30), suffix);
		let encoded = crate::util::encoded_word::encode(&subject);
		deliver(
			dir.path(),
			format!("Subject: {encoded}\r\n\r\nbody\r\n").as_bytes(),
		);
	}
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 SORT (SUBJECT) UTF-8 ALL"));
	assert!(
		response.contains("* SORT 2 1\r\n"),
		"folded subject sort ignored continuation: {response}"
	);
}

#[test]
fn sort_subject_normalizes_plain_and_encoded_case() {
	for prefix in ["", "Re: ", "Fwd: "] {
		let dir = tempfile::tempdir().expect("tempdir");
		for subject in [
			format!("{prefix}apple"),
			format!("{prefix}Banana"),
			format!("=?UTF-8?Q?{}Apricot?=", prefix.replace(' ', "_")),
			format!("=?UTF-8?Q?{}blueberry?=", prefix.replace(' ', "_")),
		] {
			deliver(
				dir.path(),
				format!("Subject: {subject}\r\n\r\nbody\r\n").as_bytes(),
			);
		}
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		let response = text(&session.command_line("a3 SORT (SUBJECT) UTF-8 ALL"));
		assert!(
			response.contains("* SORT 1 3 2 4\r\n"),
			"subject case changed ordering: {response}"
		);
	}
}
