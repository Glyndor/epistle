//! SORT by the address and subject keys as Dovecot's imaptest
//! `sort-addresses` and `sort-subject` scripts check them.

use super::sort_dates::{append_dated, assert_sorts};
use super::*;

#[test]
fn sort_addresses_compare_the_first_mailbox_local_part() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	for (hour, headers, body) in [
		(
			0,
			"From: user2@domain2.org\r\nTo: foo bar <user2@domain2.org>\r\n\
			 Cc: user2@domain2.org (foo bar)",
			"1",
		),
		(
			1,
			"From: user2@domain1.org\r\nTo: user2@domain1.org\r\nCc: user2: blah@domain1.org;",
			"2",
		),
		(
			2,
			"From: user1@domain1.org\r\nTo: user1@domain1.org\r\nCc: user1@domain1.org",
			"3",
		),
	] {
		append_dated(
			&mut session,
			&format!("22-Feb-2008 {hour:02}:06:23 +0000"),
			&format!("{headers}\r\n\r\n{body}\r\n"),
		);
	}
	assert_sorts(
		&mut session,
		&[
			("from", "3 1 2"),
			("to", "3 1 2"),
			("cc", "3 1 2"),
			("reverse from", "1 2 3"),
			("reverse to", "1 2 3"),
			("reverse cc", "1 2 3"),
			("from reverse arrival", "3 2 1"),
			("to reverse arrival", "3 2 1"),
			("cc reverse arrival", "3 2 1"),
		],
	);
}

#[test]
fn sort_addresses_fold_case_and_put_a_missing_field_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	for headers in ["From: Bob@x.org", "From: alice@y.org", "Subject: none"] {
		append_dated(
			&mut session,
			"22-Feb-2008 00:00:00 +0000",
			&format!("{headers}\r\n\r\nx\r\n"),
		);
	}
	assert_sorts(&mut session, &[("from", "3 2 1")]);
}
