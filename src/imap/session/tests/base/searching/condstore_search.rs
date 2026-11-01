//! CONDSTORE enabling and MODSEQ search results, replayed from Dovecot's
//! imaptest `esearch-condstore` script (RFC 7162 §3.1).

use super::*;

/// The number inside the first `MODSEQ (n)` of `response`.
fn modseq_in(response: &str) -> u64 {
	let start = response.find("MODSEQ (").expect("a MODSEQ item") + "MODSEQ (".len();
	let len = response[start..].find(')').expect("closing paren");
	response[start..start + len].parse().expect("a number")
}

fn session_with_four_messages() -> (tempfile::TempDir, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	for n in 1..=4 {
		deliver(
			dir.path(),
			format!("Subject: {n}\r\n\r\n{n}\r\n").as_bytes(),
		);
	}
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	(dir, session)
}

#[test]
fn first_enabling_command_announces_highestmodseq_and_stores_report_modseq() {
	let (_dir, mut session) = session_with_four_messages();
	let plain = text(&session.command_line("b store 1 +flags \\flagged"));
	assert!(!plain.contains("MODSEQ"), "{plain}");

	let first = text(&session.command_line("c fetch 1 modseq"));
	assert!(first.starts_with("* OK [HIGHESTMODSEQ "), "{first}");
	assert!(first.contains("* 1 FETCH (MODSEQ ("), "{first}");
	let again = text(&session.command_line("d fetch 1 modseq"));
	assert!(!again.contains("HIGHESTMODSEQ"), "{again}");

	let stored = text(&session.command_line("e store 2 +flags \\seen"));
	assert!(stored.contains("* 2 FETCH (UID 2 MODSEQ ("), "{stored}");
	assert!(stored.contains("FLAGS (\\Seen)"), "{stored}");
}

#[test]
fn modseq_search_reports_the_highest_modseq_of_the_returned_messages() {
	let (_dir, mut session) = session_with_four_messages();
	session.command_line("b fetch 1 modseq");
	let mut modseq = [0u64; 5];
	for n in [1, 3, 2, 4] {
		let stored = text(&session.command_line(&format!("c store {n} +flags \\seen")));
		modseq[n] = modseq_in(&stored);
	}
	let criteria = r#"modseq "/flags/\\seen" all"#;
	for (command, expected) in [
		(
			format!("return (min) 1:3 {criteria} 1"),
			format!(" MIN 1 MODSEQ {}", modseq[1]),
		),
		(
			format!("return (max) 1:3 {criteria} 1"),
			format!(" MAX 3 MODSEQ {}", modseq[3]),
		),
		(
			format!("return () 1:3 {criteria} 1"),
			format!(" ALL 1:3 MODSEQ {}", modseq[2]),
		),
		(
			format!("return (min max) 2:3 {criteria} 1"),
			format!(" MIN 2 MAX 3 MODSEQ {}", modseq[2]),
		),
		(
			format!("return (all) 2:3 {criteria} {}", modseq[3]),
			format!(" ALL 2:3 MODSEQ {}", modseq[2]),
		),
		(
			format!("return (all) 2:3 {criteria} {}", modseq[2]),
			format!(" ALL 2 MODSEQ {}", modseq[2]),
		),
		(
			format!("return (all) 2:3 {criteria} {}", modseq[4]),
			String::new(),
		),
	] {
		assert_eq!(
			text(&session.command_line(&format!("s search {command}"))),
			format!("* ESEARCH (TAG \"s\"){expected}\r\ns OK SEARCH completed\r\n"),
			"search {command}"
		);
	}
	assert_eq!(
		text(&session.command_line(&format!("s search modseq {}", modseq[2]))),
		format!(
			"* SEARCH 2 4 (MODSEQ {})\r\ns OK SEARCH completed\r\n",
			modseq[4]
		)
	);
	assert_eq!(
		text(&session.command_line(&format!("s search modseq {}", modseq[4] + 1))),
		"* SEARCH\r\ns OK SEARCH completed\r\n"
	);
}

#[test]
fn modseq_entry_type_must_be_priv_shared_or_all() {
	let (_dir, mut session) = session_with_four_messages();
	let response = text(&session.command_line(r#"s search modseq "/flags/\\seen" other 1"#));
	assert!(response.starts_with("s BAD"), "{response}");
}

#[test]
fn search_by_modseq() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\none\r\n");
	deliver(dir.path(), b"From: c@d\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	// Bump message 2's mod-sequence (now 2); message 1 stays at 1.
	session.command_line("a3 STORE 2 +FLAGS (\\Seen)");

	// MODSEQ 2 matches only the changed message.
	let response = text(&session.command_line("a4 SEARCH MODSEQ 2"));
	assert!(response.contains("* SEARCH 2 (MODSEQ 2)\r\n"), "{response}");

	// MODSEQ 1 matches both.
	let response = text(&session.command_line("a5 SEARCH MODSEQ 1"));
	assert!(
		response.contains("* SEARCH 1 2 (MODSEQ 2)\r\n"),
		"{response}"
	);
}
