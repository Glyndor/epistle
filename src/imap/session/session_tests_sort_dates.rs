//! SORT by ARRIVAL, DATE and SIZE as Dovecot's imaptest `sort-arrival`,
//! `sort-date` and `sort-size` scripts check them: the messages are appended
//! with the INTERNALDATE of their mbox `From ` line, then sorted.

use super::*;

/// APPEND `body` to INBOX with the quoted INTERNALDATE `date`.
pub(super) fn append_dated(session: &mut Session, date: &str, body: &str) {
	let ready =
		text(&session.command_line(&format!("p APPEND INBOX \"{date}\" {{{}}}", body.len())));
	assert!(ready.starts_with("+ "), "{ready}");
	let done = text(&session.literal_done(body.as_bytes()));
	assert!(done.contains("p OK"), "{done}");
}

/// APPEND every message of an mbox text the way imaptest does: each `From `
/// line gives the INTERNALDATE, and the lines up to the next one, the blank
/// separator included, become the message with CRLF line ends.
pub(super) fn append_mbox(session: &mut Session, mbox: &str) {
	let mut messages: Vec<(String, String)> = Vec::new();
	for line in mbox.lines() {
		if let Some(from) = line.strip_prefix("From ") {
			// `user@domain  Fri Feb 22 23:00:00 2008 +0200`
			let fields: Vec<&str> = from.split_whitespace().collect();
			let zone = fields.get(6).copied().unwrap_or("+0000");
			let date = format!(
				"{}-{}-{} {} {zone}",
				fields[3], fields[2], fields[5], fields[4]
			);
			messages.push((date, String::new()));
		} else if let Some((_, body)) = messages.last_mut() {
			body.push_str(line);
			body.push_str("\r\n");
		}
	}
	for (date, body) in messages {
		append_dated(session, &date, &body);
	}
}

/// Run each SORT and compare its untagged reply.
pub(super) fn assert_sorts(session: &mut Session, cases: &[(&str, &str)]) {
	for (keys, expected) in cases {
		let response = text(&session.command_line(&format!("s SORT ({keys}) US-ASCII ALL")));
		assert_eq!(
			response.lines().next(),
			Some(format!("* SORT {expected}").as_str()),
			"sort ({keys}): {response}"
		);
	}
}

#[test]
fn append_date_time_becomes_the_internaldate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	append_dated(&mut session, "22-Feb-2008 23:00:00 +0200", "\r\n1\r\n");
	let response = text(&session.command_line("f FETCH 1 INTERNALDATE"));
	assert!(
		// The instant 2008-02-22T21:00:00Z, shown in the zone it came in.
		response.contains("INTERNALDATE \"22-Feb-2008 23:00:00 +0200\""),
		"{response}"
	);
	let response = text(&session.command_line("b APPEND INBOX \"31-Feb-2008 00:00:00 +0000\" {3}"));
	assert!(response.starts_with("b BAD"), "{response}");
}

#[test]
fn sort_arrival_follows_the_append_date() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	for (time, body) in [
		("00:00:00", "1"),
		("02:00:00", "2"),
		("01:00:00", "33"),
		("02:00:00", "44"),
		("02:00:00", "5555"),
	] {
		append_dated(
			&mut session,
			&format!("22-Feb-2008 {time} +0000"),
			&format!("\r\n{body}\r\n"),
		);
	}
	assert_sorts(
		&mut session,
		&[
			("arrival", "1 3 2 4 5"),
			("reverse arrival", "2 4 5 3 1"),
			("arrival reverse size", "1 3 5 4 2"),
		],
	);
}

#[test]
fn sort_size_breaks_ties_by_arrival_and_sequence() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	let bodies = ["1", "22", "333", "4\r\n4", "555", "66", "7777", "8"];
	for (hour, body) in bodies.iter().enumerate() {
		append_dated(
			&mut session,
			&format!("22-Feb-2008 {hour:02}:06:23 +0000"),
			&format!("Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n\r\n{body}\r\n"),
		);
	}
	assert_sorts(
		&mut session,
		&[
			("size", "1 8 2 6 3 5 4 7"),
			("reverse size", "4 7 3 5 2 6 1 8"),
			("size reverse arrival", "8 1 6 2 5 3 7 4"),
		],
	);
}

#[test]
fn sort_date_uses_the_date_header_and_falls_back_to_internaldate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	for (internal, header, body) in [
		("23:00:00", "Date: Fri, 22 Feb 2008 00:00:00 +0200", "1"),
		("22:00:00", "Date: Fri, 22 Feb 2008 02:00:00 +0200", "2"),
		("21:00:00", "Date: Fri, 22 Feb 2008 01:00:00 +0200", "33"),
		("20:00:00", "Date: Fri, 22 Feb 2008 02:00:00 +0200", "44"),
		("01:30:23", "Subject: foo", "55555"),
		("18:00:00", "Date: Fri, 22 Feb 2008 02:00:00 +0200", "6666"),
		("01:00:00", "Subject: foo bar foo bar foo bar fooo", "777"),
	] {
		append_dated(
			&mut session,
			&format!("22-Feb-2008 {internal} +0200"),
			&format!("{header}\r\n\r\n{body}\r\n"),
		);
	}
	assert_sorts(
		&mut session,
		&[
			("date", "1 3 7 5 2 4 6"),
			("reverse date", "2 4 6 5 3 7 1"),
			("date reverse size", "1 7 3 5 6 4 2"),
		],
	);
}

#[test]
fn sort_date_compares_instants_across_zones() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	// 10:00 at +0500 is 05:00 UTC, before 06:00 UTC written as 06:00 +0000.
	append_dated(
		&mut session,
		"22-Feb-2008 00:00:00 +0000",
		"Date: Fri, 22 Feb 2008 06:00:00 +0000\r\n\r\nx\r\n",
	);
	append_dated(
		&mut session,
		"22-Feb-2008 00:00:00 +0000",
		"Date: Fri, 22 Feb 2008 10:00:00 +0500\r\n\r\ny\r\n",
	);
	assert_sorts(&mut session, &[("date", "2 1")]);
}
