//! THREAD=ORDEREDSUBJECT as Dovecot's imaptest `thread-orderedsubject` and
//! `thread-orderedsubject2` scripts check it.

use super::super::searching::sort_dates::append_mbox;
use super::super::searching::sort_text::SUBJECTS_MBOX;
use super::*;

/// The messages of imaptest's `thread-orderedsubject2.mbox`: the Date header
/// runs against the arrival order, and the last four have none.
const DATED_MBOX: &str = "\
From user@domain  Fri Feb 22 23:00:01 2008 +0200
Subject: a
Date: Fri, 22 Feb 2008 22:00:10 +0200

1

From user@domain  Fri Feb 22 23:00:02 2008 +0200
Date: Fri, 22 Feb 2008 22:00:09 +0200
Subject: b

2

From user@domain  Fri Feb 22 23:00:03 2008 +0200
Date: Fri, 22 Feb 2008 22:00:08 +0200
Subject: a

3

From user@domain  Fri Feb 22 23:00:04 2008 +0200
Date: Fri, 22 Feb 2008 22:00:07 +0200
Subject: b

4

From user@domain  Fri Feb 22 22:00:30 2008 +0200
Subject: a

5

From user@domain  Fri Feb 22 22:00:29 2008 +0200
Subject: b

6

From user@domain  Fri Feb 22 22:00:28 2008 +0200
Subject: a

7

From user@domain  Fri Feb 22 22:00:27 2008 +0200
Subject: b

8

";

fn thread(session: &mut Session) -> String {
	let response = text(&session.command_line("t THREAD ORDEREDSUBJECT US-ASCII ALL"));
	assert!(response.contains("t OK THREAD completed"), "{response}");
	response.lines().next().unwrap_or_default().to_string()
}

#[test]
fn orderedsubject_groups_by_base_subject_under_the_first_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	append_mbox(&mut session, SUBJECTS_MBOX);
	assert_eq!(
		thread(&mut session),
		"* THREAD (1)(2 (7)(12)(13))(3 (5)(11))(4)(6)(8)(9 10)(14)(15)"
	);
}

#[test]
fn orderedsubject_orders_by_sent_date() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	append_mbox(&mut session, DATED_MBOX);
	assert_eq!(thread(&mut session), "* THREAD (4 (2)(8)(6))(3 (1)(7)(5))");
}
