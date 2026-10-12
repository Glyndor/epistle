//! QUOTAROOT echoes the mailbox as an astring (RFC 9208 §5.2): a name with
//! a space or a non-ASCII character must reach the client as one string.

use super::*;

fn quota_root_line(session: &mut Session, tag: &str, name: &str) -> String {
	let response = text(&session.command_line(&format!("{tag} GETQUOTAROOT \"{name}\"")));
	assert!(
		response.ends_with(&format!("{tag} OK GETQUOTAROOT completed\r\n")),
		"{response}"
	);
	response.lines().next().unwrap_or_default().to_string()
}

#[test]
fn quota_root_quotes_a_name_with_a_space() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let created = text(&session.command_line("c1 CREATE \"My Box\""));
	assert_eq!(created, "c1 OK CREATE completed\r\n");
	assert_eq!(
		quota_root_line(&mut session, "q1", "My Box"),
		"* QUOTAROOT \"My Box\" \"\""
	);
}

#[test]
fn quota_root_quotes_the_spelling_of_each_connection() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut utf8 = logged_in(dir.path());
	let enabled = text(&utf8.command_line("e1 ENABLE UTF8=ACCEPT"));
	assert_eq!(
		enabled,
		"* ENABLED UTF8=ACCEPT\r\ne1 OK ENABLE completed\r\n"
	);
	let created = text(&utf8.command_line("c1 CREATE \"Café Box\""));
	assert_eq!(created, "c1 OK CREATE completed\r\n");
	assert_eq!(
		quota_root_line(&mut utf8, "q1", "Café Box"),
		"* QUOTAROOT \"Café Box\" \"\""
	);
	let mut rev1 = logged_in(dir.path());
	assert_eq!(
		quota_root_line(&mut rev1, "q2", "Caf&AOk- Box"),
		"* QUOTAROOT \"Caf&AOk- Box\" \"\""
	);
}

#[test]
fn quota_names_the_empty_root_as_a_quoted_string() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("q1 GETQUOTA \"\""));
	assert!(response.starts_with("* QUOTA \"\" (STORAGE "), "{response}");
	assert!(
		response.ends_with("q1 OK GETQUOTA completed\r\n"),
		"{response}"
	);
}

#[test]
fn astring_escapes_quoted_specials_and_falls_back_to_a_literal() {
	use crate::imap::session::utf8::astring;
	assert_eq!(astring("My Box", false), "\"My Box\"");
	assert_eq!(astring("a\"b\\c", false), "\"a\\\"b\\\\c\"");
	assert_eq!(astring("", false), "\"\"");
	assert_eq!(astring("Café", true), "\"Café\"");
	assert_eq!(astring("Café", false), "{5}\r\nCafé");
	assert_eq!(astring("a\r\nb", true), "{4}\r\na\r\nb");
}
