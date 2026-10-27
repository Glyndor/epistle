//! Header and address searches from Dovecot's imaptest `search-header` and
//! `search-addresses` scripts, replayed with the same commands and messages.

use super::*;

fn assert_searches(session: &mut Session, cases: &[(&str, &str)]) {
	for (criteria, expected) in cases {
		assert_eq!(
			text(&session.command_line(&format!("s search {criteria}"))),
			format!("* SEARCH{expected}\r\ns OK SEARCH completed\r\n"),
			"search {criteria}"
		);
	}
}

#[test]
fn header_search_looks_at_every_field_with_that_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"Subject: hello beautiful world\r\n\r\nbody\r\n",
	);
	deliver(
		dir.path(),
		b"X-Extra: hello beautiful header\r\nX-Extra: another one\r\n\r\nbody\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	assert_searches(
		&mut session,
		&[
			("subject \"eautiful worl\"", " 1"),
			("header subject \"\"", " 1"),
			("not header subject \"\"", " 2"),
			("header x-extra \"\"", " 2"),
			("not header x-extra \"\"", " 1"),
			("header x-extra \"eautiful head\"", " 2"),
			("header x-extra \"another\"", " 2"),
		],
	);
}

#[test]
fn address_search_matches_the_parsed_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	for headers in [
		"From: user-from@domain.org\r\nTo: user-to@domain.org\r\nCc: user-cc@domain.org",
		"From: RealFrom <user-from@domain.org>\r\nTo: RealTo <user-to@domain.org>",
		"From: <user-from (comment)@ (comment) domain.org>\r\nTo: <user-to@domain.org>",
		"From: user-from@domain.org (RealFrom)\r\nTo: user-to@domain.org (RealTo)",
		"From: user-from1@domain.org, user-from2@domain.org\r\nCc: user-cc@domain.org",
		"From: RealFrom <user-from@domain.org>\r\nTo: groupname: groupuser1@domain.org, \
		 groupuser2@domain.org;,\r\n  groupname2: groupuser3@domain.org;",
		"From: RealFrom <user-from@domain.org>\r\nTo: groupname:;",
	] {
		deliver(dir.path(), format!("{headers}\r\n\r\nbody\r\n").as_bytes());
	}
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	assert_searches(
		&mut session,
		&[
			("from user-from@domain.org", " 1 2 3 4 6 7"),
			("to user-to@domain.org", " 1 2 3 4"),
			("from realfrom", " 2 4 6 7"),
			("to realto", " 2 4"),
			("header from \"\"", " 1 2 3 4 5 6 7"),
			("header to \"\"", " 1 2 3 4 6 7"),
			("from ser-fro", " 1 2 3 4 5 6 7"),
			("from ealfro", " 2 4 6 7"),
			("from user-from2", " 5"),
			("to groupname", " 6 7"),
			("to groupname2", " 6"),
			("to groupuser3", " 6"),
			("to groupuser4", ""),
		],
	);
}
