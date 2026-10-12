//! International mailbox names: modified UTF-7 for IMAP4rev1 clients and
//! raw UTF-8 once a client enables `UTF8=ACCEPT` (RFC 6855).

use super::*;

fn list_line(session: &mut Session, tag: &str) -> String {
	text(&session.command_line(&format!("{tag} LIST \"\" \"*\"")))
}

#[test]
fn rev1_client_creates_and_selects_a_modified_utf7_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let created = text(&session.command_line("c1 CREATE \"Entw&APw-rfe\""));
	assert_eq!(created, "c1 OK CREATE completed\r\n");
	let listed = list_line(&mut session, "l1");
	assert!(
		listed.contains("* LIST () \"/\" \"Entw&APw-rfe\"\r\n"),
		"{listed}"
	);
	let selected = text(&session.command_line("s1 SELECT \"Entw&APw-rfe\""));
	assert!(selected.contains("s1 OK [READ-WRITE]"), "{selected}");
}

#[test]
fn rev1_client_cannot_create_malformed_or_raw_utf8_names() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	for (tag, name) in [
		("c1", "Entw&APw"),
		("c2", "Caf&AGE-"),
		("c3", "A&-B"),
		("c4", "Café"),
	] {
		let response = text(&session.command_line(&format!("{tag} CREATE \"{name}\"")));
		assert!(
			response.starts_with(&format!("{tag} NO ")),
			"{name}: {response}"
		);
	}
}
