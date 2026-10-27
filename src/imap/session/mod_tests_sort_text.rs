//! SORT by the address and subject keys as Dovecot's imaptest
//! `sort-addresses` and `sort-subject` scripts check them.

use super::sort_dates::{append_dated, append_mbox, assert_sorts};
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

/// The messages of imaptest's `sort-subject.mbox`, which
/// `thread-orderedsubject.mbox` repeats byte for byte.
pub(super) const SUBJECTS_MBOX: &str = "\
From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: a

1

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: C

2

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: b

3

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: _

4

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: [foo] Fwd: [bar] Re: fw: b (fWd)  (fwd)

55

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: b (a)

66

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: Re: [FWD: c]

77

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: [xyz]

88

From user@domain  Fri Feb 22 23:00:00 2008 +0200

9

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: =?iso-8859-1?q?_?=

10

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: Re: =?utf-8?q?b?=

11
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: =?iso-8859-1?q?RE:_C?=

12
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: =?us-ascii?b?UmU6IGM=?=

13

The subject is 'Re: c'.
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: Ad: Re: Ad: Re: Ad: x

14

From user@domain  Fri Feb 22 23:00:00 2008 +0200
Subject: re: [fwd: [fwd: re: [fwd: babylon]]]

15
";

#[test]
fn sort_subject_compares_the_rfc_5256_base_subject() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	append_mbox(&mut session, SUBJECTS_MBOX);
	assert_sorts(
		&mut session,
		&[
			("subject", "9 10 1 14 3 5 11 6 15 2 7 12 13 8 4"),
			("reverse subject", "4 8 2 7 12 13 15 6 3 5 11 14 1 9 10"),
			(
				"subject reverse size",
				"10 9 1 14 11 5 3 6 15 13 12 7 2 8 4",
			),
		],
	);
}
