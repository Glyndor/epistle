//! Mailbox and account names never become more than one path component, so
//! a hostile CREATE / RENAME / SELECT, or an account name from a directory
//! backend, cannot reach outside `<data_dir>/accounts/<account>/`.

use super::*;
use std::collections::HashMap;

use crate::smtp::directory::Directory;

fn entries(dir: &std::path::Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(dir)
		.expect("read_dir")
		.flatten()
		.map(|entry| entry.file_name().to_string_lossy().into_owned())
		.collect();
	names.sort();
	names
}

#[test]
fn hostile_mailbox_names_are_refused_with_the_exact_response() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().join("data");
	std::fs::create_dir_all(&data).expect("data");
	let mut session = logged_in(&data);
	session.command_line("a2 CREATE Real");

	let cases = [
		(r#"b1 CREATE "../x""#, "b1 NO invalid mailbox name\r\n"),
		(r#"b2 CREATE "a/b""#, "b2 NO invalid mailbox name\r\n"),
		(r#"b3 CREATE "..""#, "b3 NO invalid mailbox name\r\n"),
		(
			r#"b4 CREATE "Archive\\2024""#,
			"b4 NO invalid mailbox name\r\n",
		),
		(r#"b5 RENAME Real "../x""#, "b5 NO cannot rename\r\n"),
		(r#"b6 RENAME "../Real" Other"#, "b6 NO cannot rename\r\n"),
		(
			r#"b7 DELETE "../Real""#,
			"b7 NO cannot delete this mailbox\r\n",
		),
		(r#"b8 SELECT "../Real""#, "b8 NO no such mailbox\r\n"),
		(r#"b9 SELECT "../../x""#, "b9 NO no such mailbox\r\n"),
	];
	for (command, expected) in cases {
		let reply = text(&session.command_line(command));
		assert_eq!(reply, expected, "reply to {command}");
	}
	// Nothing was created, moved or removed anywhere.
	assert_eq!(entries(outer.path()), vec!["data".to_string()]);
	assert_eq!(entries(&data.join("accounts")), vec!["alice".to_string()]);
	let folders = entries(&data.join("accounts/alice/folders"));
	assert!(folders.iter().any(|name| name == "Real"), "{folders:?}");
	assert!(
		!folders.iter().any(|name| name == "x" || name == "Other"),
		"no folder was created by a refused name: {folders:?}"
	);
}

#[test]
fn legitimate_names_still_work_through_the_session() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	for (command, expected) in [
		("c1 CREATE Work", "c1 OK CREATE completed\r\n"),
		(r#"c2 CREATE "Sent Items""#, "c2 OK CREATE completed\r\n"),
		("c3 CREATE Old.2024", "c3 OK CREATE completed\r\n"),
		("c4 RENAME Work Projects", "c4 OK RENAME completed\r\n"),
		("c5 DELETE Old.2024", "c5 OK DELETE completed\r\n"),
	] {
		assert_eq!(text(&session.command_line(command)), expected, "{command}");
	}
	let folders = entries(&dir.path().join("accounts/alice/folders"));
	for expected in ["Projects", "Sent Items"] {
		assert!(
			folders.iter().any(|name| name == expected),
			"folder {expected} missing from {folders:?}"
		);
	}
	assert!(
		!folders
			.iter()
			.any(|name| name == "Old.2024" || name == "Work")
	);
}

/// A directory backend can name an account anything; the filesystem layer
/// must still refuse it.
fn hostile_account_session(data: &std::path::Path, account: &str) -> Session {
	let password = uuid::Uuid::new_v4().to_string();
	let directory = Directory::new(
		["example.org".to_string()],
		[("evil@example.org".to_string(), account.to_string())],
	)
	.with_password_hashes(HashMap::from([(
		account.to_string(),
		crate::smtp::auth::tests::hash(&password),
	)]));
	let mut session = Session::new(
		"mail.example.org",
		data.to_path_buf(),
		std::sync::Arc::new(directory),
	);
	let reply = text(&session.command_line(&format!("a1 LOGIN evil@example.org {password}")));
	assert!(reply.contains("a1 OK"), "login: {reply}");
	session
}

#[test]
fn an_account_name_with_a_separator_reaches_no_directory() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().join("data");
	std::fs::create_dir_all(data.join("accounts")).expect("accounts");
	let mut session = hostile_account_session(&data, "../evil");
	for (command, expected) in [
		("d1 CREATE Work", "d1 NO invalid path component\r\n"),
		("d2 SELECT INBOX", "d2 NO no such mailbox\r\n"),
		("d3 DELETE Work", "d3 NO invalid path component\r\n"),
		("d4 RENAME Work Other", "d4 NO invalid path component\r\n"),
	] {
		assert_eq!(text(&session.command_line(command)), expected, "{command}");
	}
	assert_eq!(entries(outer.path()), vec!["data".to_string()]);
	assert!(entries(&data.join("accounts")).is_empty());
}
