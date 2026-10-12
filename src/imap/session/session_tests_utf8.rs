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

fn utf8_session(dir: &std::path::Path) -> Session {
	let mut session = logged_in(dir);
	let enabled = text(&session.command_line("e1 ENABLE UTF8=ACCEPT"));
	assert_eq!(
		enabled,
		"* ENABLED UTF8=ACCEPT\r\ne1 OK ENABLE completed\r\n"
	);
	session
}

#[test]
fn utf8_accept_lists_raw_utf8_and_rev1_lists_modified_utf7() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut utf8 = utf8_session(dir.path());
	let created = text(&utf8.command_line("c1 CREATE \"Entwürfe\""));
	assert_eq!(created, "c1 OK CREATE completed\r\n");
	let listed = list_line(&mut utf8, "l1");
	assert!(
		listed.contains("* LIST () \"/\" \"Entwürfe\"\r\n"),
		"{listed}"
	);

	let mut rev1 = logged_in(dir.path());
	let listed = list_line(&mut rev1, "l2");
	assert!(
		listed.contains("* LIST () \"/\" \"Entw&APw-rfe\"\r\n"),
		"{listed}"
	);
	assert!(!listed.contains("Entwürfe"), "{listed}");
}

#[test]
fn utf8_accept_addresses_mailboxes_by_their_utf8_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = utf8_session(dir.path());
	session.command_line("c1 CREATE \"Café\"");
	let status = text(&session.command_line("s1 STATUS \"Café\" (MESSAGES)"));
	assert_eq!(
		status,
		"* STATUS \"Café\" (MESSAGES 0)\r\ns1 OK STATUS completed\r\n"
	);
	let rights = text(&session.command_line("r1 MYRIGHTS \"Café\""));
	assert!(rights.starts_with("* MYRIGHTS \"Café\" "), "{rights}");
	let renamed = text(&session.command_line("r2 RENAME \"Café\" \"Thé\""));
	assert_eq!(renamed, "r2 OK RENAME completed\r\n");
	let selected = text(&session.command_line("s2 SELECT \"Thé\""));
	assert!(selected.contains("s2 OK [READ-WRITE]"), "{selected}");
	// On disk the folder carries the modified UTF-7 spelling.
	assert!(dir.path().join("accounts/alice/folders/Th&AOk-").is_dir());
}

#[test]
fn utf8_accept_takes_ampersand_literally() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = utf8_session(dir.path());
	// Under UTF-8 this is a name with a literal `&`, not an encoded "Café".
	let created = text(&session.command_line("c1 CREATE \"Caf&AOk-\""));
	assert!(created.starts_with("c1 NO "), "{created}");
}

#[test]
fn imap4rev2_lists_raw_utf8_names() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut rev1 = logged_in(dir.path());
	rev1.command_line("c1 CREATE \"Entw&APw-rfe\"");
	let mut rev2 = logged_in(dir.path());
	rev2.command_line("e1 ENABLE IMAP4rev2");
	let listed = list_line(&mut rev2, "l1");
	assert!(listed.contains("\"/\" \"Entwürfe\"\r\n"), "{listed}");
}

#[test]
fn utf8_accept_refuses_a_search_charset() {
	// RFC 6855 §3: after ENABLE UTF8=ACCEPT a SEARCH with CHARSET is a BAD.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = utf8_session(dir.path());
	session.command_line("s1 SELECT INBOX");
	let search = text(&session.command_line("s2 SEARCH CHARSET UTF-8 ALL"));
	assert!(search.starts_with("s2 BAD "), "{search}");
	assert!(!search.contains("* SEARCH"), "{search}");
}
