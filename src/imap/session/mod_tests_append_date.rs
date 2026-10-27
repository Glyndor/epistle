//! APPEND keeps its date-time as the INTERNALDATE, in the zone it was given
//! (RFC 9051 §6.3.12), and date searches read the date in that zone.

use super::*;

/// Append one message per date-time to INBOX, then select it.
fn appended(dates: &[&str]) -> (tempfile::TempDir, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let message = b"Subject: x\r\n\r\nbody\r\n";
	for (i, date) in dates.iter().enumerate() {
		let line = format!("a{i} APPEND INBOX \"{date}\" {{{}}}", message.len());
		assert!(
			text(&session.command_line(&line)).starts_with("+ "),
			"{line}"
		);
		let reply = text(&session.literal_done(message));
		assert!(reply.contains(&format!("a{i} OK")), "{reply}");
	}
	session.command_line("s SELECT INBOX");
	(dir, session)
}

fn search(session: &mut Session, criteria: &str) -> String {
	text(&session.command_line(&format!("q SEARCH {criteria}")))
		.lines()
		.next()
		.unwrap_or_default()
		.to_string()
}

const DATES: [&str; 4] = [
	"24-Mar-2007 23:00:00 +0200",
	"25-Mar-2007 00:00:00 +0200",
	"25-Mar-2007 04:00:00 +0300",
	"26-Mar-2007 00:00:00 +0300",
];

#[test]
fn internaldate_is_the_appended_date_time() {
	let (_dir, mut session) = appended(&DATES);
	let reply = text(&session.command_line("f FETCH 1:4 (INTERNALDATE)"));
	for (i, date) in DATES.iter().enumerate() {
		let line = format!("* {} FETCH (INTERNALDATE \"{date}\")\r\n", i + 1);
		assert!(reply.contains(&line), "{line:?} in {reply}");
	}
}

#[test]
fn date_searches_use_the_appended_zone() {
	let (_dir, mut session) = appended(&DATES);
	assert_eq!(search(&mut session, "ON 24-Mar-2007"), "* SEARCH 1");
	assert_eq!(search(&mut session, "ON 25-Mar-2007"), "* SEARCH 2 3");
	assert_eq!(search(&mut session, "ON 26-Mar-2007"), "* SEARCH 4");
	assert_eq!(search(&mut session, "BEFORE 25-Mar-2007"), "* SEARCH 1");
	assert_eq!(search(&mut session, "SINCE 26-Mar-2007"), "* SEARCH 4");
	assert_eq!(search(&mut session, "NOT ON 25-Mar-2007"), "* SEARCH 1 4");
}

#[test]
fn copy_keeps_the_internaldate() {
	let (_dir, mut session) = appended(&DATES[1..2]);
	assert!(text(&session.command_line("c1 CREATE box")).contains("c1 OK"));
	assert!(text(&session.command_line("c2 COPY 1 box")).contains("c2 OK"));
	session.command_line("s SELECT box");
	let reply = text(&session.command_line("f FETCH 1 (INTERNALDATE)"));
	assert!(
		reply.starts_with("* 1 FETCH (INTERNALDATE \"25-Mar-2007 00:00:00 +0200\")"),
		"{reply}"
	);
}

#[test]
fn a_malformed_date_time_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	for date in [
		"31-Feb-2007 00:00:00 +0200",
		"25-Mar-2007 24:00:00 +0000",
		"x",
	] {
		let reply = text(&session.command_line(&format!("a APPEND INBOX \"{date}\" {{4}}")));
		assert!(reply.starts_with("a BAD"), "{date}: {reply}");
	}
}

#[test]
fn replace_keeps_its_date_time_and_zone() {
	let (_dir, mut session) = appended(&DATES[..1]);
	let message = b"Subject: y\r\n\r\nnew\r\n";
	let line = format!(
		"r REPLACE 1 INBOX \"26-Mar-2007 00:00:00 +0300\" {{{}}}",
		message.len()
	);
	assert!(
		text(&session.command_line(&line)).starts_with("+ "),
		"{line}"
	);
	let reply = text(&session.literal_done(message));
	assert!(reply.contains("r OK"), "{reply}");
	let reply = text(&session.command_line("f FETCH 1:* (INTERNALDATE)"));
	assert!(
		reply.contains("(INTERNALDATE \"26-Mar-2007 00:00:00 +0300\")"),
		"{reply}"
	);
	assert_eq!(search(&mut session, "ON 26-Mar-2007"), "* SEARCH 1");
}
