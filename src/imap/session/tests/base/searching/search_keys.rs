//! Search keys exercised by Dovecot's imaptest `search-body`, `search-date`
//! and `nil` scripts, replayed with the same lowercase commands.

use super::*;

fn search(session: &mut Session, criteria: &str) -> String {
	text(&session.command_line(&format!("s search {criteria}")))
}

#[test]
fn body_key_matches_the_body_only_and_text_also_the_headers() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n\r\nasdfghjkl zxcvbnm\r\n",
	);
	deliver(
		dir.path(),
		b"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\nSubject: qwertyuiop\r\n\r\nasdfghjkl\r\n",
	);
	deliver(
		dir.path(),
		b"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\nX-Header: qwertyuiop\r\n\r\nzxcvbnm\r\n",
	);
	deliver(
		dir.path(),
		b"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n\r\nzxcvbnm qwertyuiop\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	for (criteria, expected) in [
		("text asdfghjkl", "1 2"),
		("text qwertyuiop", "2 3 4"),
		("body asdfghjkl", "1 2"),
		("body zxcvbnm", "1 3 4"),
		("body qwertyuiop", "4"),
		("body wertyuio", "4"),
		("body xcvbn", "1 3 4"),
	] {
		assert_eq!(
			search(&mut session, criteria),
			format!("* SEARCH {expected}\r\ns OK SEARCH completed\r\n"),
			"search {criteria}"
		);
	}
}

#[test]
fn body_nil_is_the_string_nil() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"Date: Sat, 24 Mar 2007 23:00:00 +0200\r\nSubject: NiL\r\n\r\nnil\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	for criteria in ["subject NIL", "body nil"] {
		assert_eq!(
			search(&mut session, criteria),
			"* SEARCH 1\r\ns OK SEARCH completed\r\n",
			"search {criteria}"
		);
	}
}

#[test]
fn sent_keys_compare_the_date_header_ignoring_time_and_zone() {
	let dir = tempfile::tempdir().expect("tempdir");
	for date in [
		"Sat, 24 Mar 2007 23:00:00 +0200",
		"Sun, 25 Mar 2007 00:00:00 +0200",
		"Sun, 25 Mar 2007 04:00:00 +0300",
		"Sun, 25 Mar 2007 23:00:00 +0300",
		"Mon, 26 Mar 2007 00:00:00 +0300",
	] {
		deliver(
			dir.path(),
			format!("Date: {date}\r\n\r\nbody\r\n").as_bytes(),
		);
	}
	deliver(dir.path(), b"Subject: no date\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	for (criteria, expected) in [
		("sentbefore 24-mar-2007", ""),
		("sentbefore 25-mar-2007", " 1"),
		("sentbefore 26-Mar-2007", " 1 2 3 4"),
		("senton 23-mar-2007", ""),
		("senton 24-mar-2007", " 1"),
		("SENTON 25-MAR-2007", " 2 3 4"),
		("1:5 sentsince 25-mar-2007", " 2 3 4 5"),
		("1:5 sentsince 27-mar-2007", ""),
		("1:5 not senton 25-mar-2007", " 1 5"),
	] {
		assert_eq!(
			search(&mut session, criteria),
			format!("* SEARCH{expected}\r\ns OK SEARCH completed\r\n"),
			"search {criteria}"
		);
	}
}

#[test]
fn sent_dates_accept_a_single_digit_day_and_reject_a_bad_month() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"Date: Fri, 2 Mar 2007 10:00:00 +0000\r\n\r\nbody\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	assert_eq!(
		search(&mut session, "senton 2-mar-2007"),
		"* SEARCH 1\r\ns OK SEARCH completed\r\n"
	);
	assert!(
		search(&mut session, "senton 2-xyz-2007").starts_with("s BAD"),
		"an unknown month is a syntax error"
	);
}
