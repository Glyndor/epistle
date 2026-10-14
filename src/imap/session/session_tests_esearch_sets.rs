//! ESEARCH result sets as Dovecot's imaptest `esearch` script expects them:
//! `ALL` carries a compact sequence-set with ranges.

use super::*;

#[test]
fn esearch_all_joins_consecutive_numbers_into_ranges() {
	let dir = tempfile::tempdir().expect("tempdir");
	for n in 1..=7 {
		deliver(
			dir.path(),
			format!("Subject: {n}\r\n\r\n{n}\r\n").as_bytes(),
		);
	}
	let mut session = logged_in(dir.path());
	session.command_line("a select INBOX");
	session.command_line("b store 4 +flags \\deleted");
	session.command_line("c expunge");
	for (command, expected) in [
		("search return (all) all", "* ESEARCH (TAG \"s\") ALL 1:6"),
		("search return () all", "* ESEARCH (TAG \"s\") ALL 1:6"),
		(
			"search return (min max count) all",
			"* ESEARCH (TAG \"s\") MIN 1 MAX 6 COUNT 6",
		),
		(
			"uid search return (all) all",
			"* ESEARCH (TAG \"s\") UID ALL 1:3,5:7",
		),
		("search return () 1000", "* ESEARCH (TAG \"s\")"),
		(
			"search return (count) 1000",
			"* ESEARCH (TAG \"s\") COUNT 0",
		),
		("uid search return () 1000", "* ESEARCH (TAG \"s\") UID"),
	] {
		assert_eq!(
			text(&session.command_line(&format!("s {command}"))),
			format!("{expected}\r\ns OK SEARCH completed\r\n"),
			"{command}"
		);
	}
	session.command_line("d store 2,4 +flags \\seen");
	assert_eq!(
		text(&session.command_line("s uid search return (all) seen")),
		"* ESEARCH (TAG \"s\") UID ALL 2,5\r\ns OK SEARCH completed\r\n"
	);
}
