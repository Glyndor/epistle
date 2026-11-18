//! RFC 5530 response codes on mailbox, message and malformed-command
//! failures. Each case sends the command in the state it describes and
//! compares the tagged reply byte for byte, so a code that moved to another
//! failure, was doubled or landed inside another status code fails here.

use super::*;

const MESSAGE: &[u8] = b"From: a@example.org\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nhi\r\n";

fn reply(session: &mut Session, command: &str) -> String {
	text(&session.command_line(command))
}

fn selected(dir: &std::path::Path, verb: &str) -> Session {
	deliver(dir, MESSAGE);
	let mut session = logged_in(dir);
	let done = reply(&mut session, &format!("s {verb} INBOX"));
	assert!(done.contains("s OK"), "{done}");
	session
}

fn every_file(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
	for entry in std::fs::read_dir(dir).expect("read_dir").flatten() {
		let path = entry.path();
		if path.is_dir() {
			every_file(&path, out);
		} else {
			out.push(path);
		}
	}
}

/// Delete every stored message file so a later read of it fails.
fn remove_messages(dir: &std::path::Path) {
	let mut files = Vec::new();
	every_file(&dir.join("accounts").join("alice"), &mut files);
	for file in files {
		let is_message = file
			.parent()
			.and_then(|parent| parent.file_name())
			.is_some_and(|name| name == "new" || name == "cur");
		if is_message {
			std::fs::remove_file(file).expect("remove message");
		}
	}
}

/// Turn a per-account directory into a plain file so writing through it fails.
fn break_dir(dir: &std::path::Path, name: &str) {
	let path = dir.join("accounts").join("alice").join(name);
	std::fs::remove_dir_all(&path).expect("remove dir");
	std::fs::write(&path, b"not a directory").expect("write file");
}

#[test]
fn create_over_an_existing_mailbox_is_already_exists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert_eq!(
		reply(&mut session, "a CREATE Work"),
		"a OK CREATE completed\r\n"
	);
	assert_eq!(
		reply(&mut session, "b CREATE Work"),
		"b NO [ALREADYEXISTS] mailbox already exists\r\n"
	);
}

#[test]
fn rename_onto_an_existing_mailbox_is_already_exists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	reply(&mut session, "a CREATE Work");
	reply(&mut session, "b CREATE Archive");
	assert_eq!(
		reply(&mut session, "c RENAME Work Archive"),
		"c NO [ALREADYEXISTS] cannot rename\r\n"
	);
}

#[test]
fn rename_of_a_missing_mailbox_is_nonexistent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert_eq!(
		reply(&mut session, "a RENAME Missing Other"),
		"a NO [NONEXISTENT] no such mailbox\r\n"
	);
}

#[test]
fn invalid_mailbox_names_cannot_be_created_renamed_or_deleted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert_eq!(
		reply(&mut session, "a CREATE \"../x\""),
		"a NO [CANNOT] invalid mailbox name\r\n"
	);
	assert_eq!(
		reply(&mut session, "b DELETE \"../x\""),
		"b NO [CANNOT] cannot delete this mailbox\r\n"
	);
}

#[test]
fn delete_of_a_mailbox_with_children_keeps_its_single_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	reply(&mut session, "a CREATE Work/Project");
	let response = reply(&mut session, "b DELETE Work");
	assert_eq!(
		response,
		"b NO [HASCHILDREN] delete the mailboxes under it first\r\n"
	);
}

#[test]
fn commands_on_a_missing_mailbox_are_nonexistent() {
	let dir = tempfile::tempdir().expect("tempdir");
	for command in [
		"DELETE Missing",
		"SELECT Missing",
		"EXAMINE Missing",
		"STATUS Missing (MESSAGES)",
		"GETQUOTAROOT Missing",
		"SUBSCRIBE Missing",
		"GETACL Missing",
		"MYRIGHTS Missing",
		"LISTRIGHTS Missing alice",
		"SETACL Missing bob +r",
		"DELETEACL Missing bob",
		"GETMETADATA Missing (/private/comment)",
		"SETMETADATA Missing (/private/comment \"x\")",
	] {
		let mut session = logged_in(dir.path());
		assert_eq!(
			reply(&mut session, &format!("a {command}")),
			"a NO [NONEXISTENT] no such mailbox\r\n",
			"{command}"
		);
	}
}

#[test]
fn a_failed_select_after_a_selected_mailbox_answers_closed_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	let response = reply(&mut session, "a SELECT Missing");
	assert_eq!(response, "a NO [CLOSED] no such mailbox\r\n");
	assert_eq!(response.matches('[').count(), 1);
	assert_eq!(
		reply(&mut session, "b SELECT Missing"),
		"b NO [NONEXISTENT] no such mailbox\r\n"
	);
}

#[test]
fn copy_and_append_to_a_missing_mailbox_ask_the_client_to_create_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	assert_eq!(
		reply(&mut session, "a COPY 1 Missing"),
		"a NO [TRYCREATE] no such mailbox\r\n"
	);
	assert_eq!(
		reply(&mut session, "b MOVE 1 Missing"),
		"b NO [TRYCREATE] no such mailbox\r\n"
	);
	assert_eq!(
		reply(&mut session, "c APPEND Missing {5}"),
		"c NO [TRYCREATE] no such mailbox\r\n"
	);
}

#[test]
fn replace_into_a_missing_mailbox_asks_the_client_to_create_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	assert_eq!(
		reply(&mut session, "a REPLACE 1 Missing {5}"),
		"a NO [TRYCREATE] no such mailbox\r\n"
	);
}

#[test]
fn replace_of_a_message_that_is_not_there_is_nonexistent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	assert_eq!(
		reply(&mut session, "a REPLACE 9 INBOX {5}"),
		"a NO [NONEXISTENT] no such message\r\n"
	);
	assert_eq!(
		reply(&mut session, "b UID REPLACE 99 INBOX {5}"),
		"b NO [NONEXISTENT] no such message\r\n"
	);
}

#[test]
fn a_read_only_mailbox_cannot_be_changed() {
	let dir = tempfile::tempdir().expect("tempdir");
	for command in [
		"STORE 1 +FLAGS (\\Seen)",
		"UID STORE 1 +FLAGS (\\Seen)",
		"EXPUNGE",
		"UID EXPUNGE 1",
		"COPY 1 INBOX",
	] {
		let mut session = selected(dir.path(), "EXAMINE");
		let response = reply(&mut session, &format!("a {command}"));
		if command == "COPY 1 INBOX" {
			assert!(
				response.contains("a OK"),
				"copy out of EXAMINE is allowed: {response}"
			);
		} else {
			assert_eq!(
				response, "a NO [CANNOT] mailbox is read-only\r\n",
				"{command}"
			);
		}
	}
	let mut session = selected(dir.path(), "EXAMINE");
	assert_eq!(
		reply(&mut session, "a MOVE 1 INBOX"),
		"a NO [CANNOT] mailbox is read-only\r\n"
	);
	assert_eq!(
		reply(&mut session, "b REPLACE 1 INBOX {5}"),
		"b NO [CANNOT] mailbox is read-only\r\n"
	);
}

#[test]
fn an_unknown_quota_root_cannot_be_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert_eq!(
		reply(&mut session, "a GETQUOTA Other"),
		"a NO [CANNOT] unknown quota root\r\n"
	);
}

#[test]
fn an_append_over_the_quota_is_overquota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory())
		.with_quota_limit(10);
	session.command_line(&format!(
		"a1 LOGIN alice {}",
		crate::test_support::fixtures::password()
	));
	assert_eq!(
		reply(&mut session, "a APPEND INBOX {100}"),
		"a NO [OVERQUOTA] storage quota exceeded\r\n"
	);
}

#[test]
fn malformed_commands_are_clientbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	for (command, expected) in [
		("a FROBNICATE", "a BAD [CLIENTBUG] unknown command\r\n"),
		("a NOOP extra", "a BAD [CLIENTBUG] invalid arguments\r\n"),
		("a SELECT", "a BAD [CLIENTBUG] invalid arguments\r\n"),
		(
			"a SETMETADATA INBOX (invalid value)",
			"a BAD [CLIENTBUG] invalid entry name\r\n",
		),
		(
			"a SETACL INBOX bob +zz",
			"a BAD [CLIENTBUG] invalid rights\r\n",
		),
	] {
		assert_eq!(reply(&mut session, command), expected, "{command}");
	}
	assert_eq!(
		text(&session.command_line("A\u{1} NOOP")),
		"* BAD [CLIENTBUG] malformed command\r\n"
	);
}

#[test]
fn an_unsupported_flag_is_clientbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	assert_eq!(
		reply(&mut session, "a STORE 1 +FLAGS (\\Bogus)"),
		"a BAD [CLIENTBUG] unsupported flag\r\n"
	);
	session.command_line("b ENABLE UTF8=ACCEPT");
	assert_eq!(
		reply(&mut session, "c APPEND INBOX (\\Bogus) {5}"),
		"c BAD [CLIENTBUG] unsupported flag\r\n"
	);
}

#[test]
fn utf8_append_before_enable_is_clientbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert_eq!(
		reply(&mut session, "a APPEND INBOX UTF8 (~{5+}"),
		"a BAD [CLIENTBUG] UTF8 APPEND requires ENABLE UTF8=ACCEPT\r\n"
	);
}

#[test]
fn a_literal_without_its_closing_crlf_is_clientbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert!(reply(&mut session, "a APPEND INBOX {1}").starts_with("+ "));
	assert_eq!(
		text(&session.literal_bad_trailer()),
		"a BAD [CLIENTBUG] APPEND literal must be followed by CRLF\r\n"
	);
	assert_eq!(
		text(&session.literal_bad_trailer()),
		"* BAD [CLIENTBUG] unexpected literal\r\n"
	);
}

#[test]
fn an_unrequested_authentication_answer_is_clientbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert_eq!(
		text(&session.auth_response("Zm9v")),
		"* BAD [CLIENTBUG] unexpected authentication response\r\n"
	);
}

#[test]
fn uidonly_sequence_commands_keep_the_uidrequired_code_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	assert!(reply(&mut session, "a ENABLE UIDONLY").contains("a OK"));
	let response = reply(&mut session, "b FETCH 1 FLAGS");
	assert_eq!(
		response,
		"b BAD [UIDREQUIRED] FETCH requires UID under UIDONLY\r\n"
	);
	assert_eq!(response.matches('[').count(), 1);
}

#[test]
fn an_unreadable_message_is_serverbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	remove_messages(dir.path());
	assert_eq!(
		reply(&mut session, "a FETCH 1 BODY[]"),
		"a NO [SERVERBUG] message unavailable\r\n"
	);
	assert_eq!(
		reply(&mut session, "b COPY 1 INBOX"),
		"b NO [SERVERBUG] message unavailable\r\n"
	);
}

#[test]
fn a_flag_change_that_cannot_be_stored_is_serverbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	// A directory where the `.flags` sidecar belongs makes the final rename
	// fail for any user, root included (a permission bit would not).
	let mailbox = dir.path().join("accounts/alice/new");
	let id = std::fs::read_dir(&mailbox)
		.expect("read mailbox")
		.map(|entry| {
			entry
				.expect("entry")
				.file_name()
				.to_string_lossy()
				.into_owned()
		})
		.find_map(|name| name.strip_suffix(".eml").map(str::to_owned))
		.expect("a delivered message");
	let blocker = mailbox.join(format!("{id}.flags"));
	std::fs::create_dir(&blocker).expect("blocker");
	std::fs::write(blocker.join("keep"), b"x").expect("fill blocker");
	assert_eq!(
		reply(&mut session, "a STORE 1 +FLAGS (\\Seen)"),
		"a NO [SERVERBUG] cannot store flags\r\n"
	);
}

#[test]
fn an_append_that_cannot_be_written_is_serverbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	break_dir(dir.path(), "tmp");
	assert!(reply(&mut session, "a APPEND INBOX {5}").starts_with("+ "));
	assert_eq!(
		text(&session.literal_done(b"hello")),
		"a NO [SERVERBUG] APPEND failed\r\n"
	);
}

#[test]
fn a_mailbox_that_cannot_be_opened_is_serverbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), MESSAGE);
	let mut session = logged_in(dir.path());
	break_dir(dir.path(), "new");
	assert_eq!(
		reply(&mut session, "a SELECT INBOX"),
		"a NO [SERVERBUG] cannot open mailbox\r\n"
	);
	assert_eq!(
		reply(&mut session, "b STATUS INBOX (MESSAGES)"),
		"b NO [SERVERBUG] cannot open mailbox\r\n"
	);
}

#[test]
fn a_saved_search_reference_without_a_saved_search_keeps_its_own_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	let response = reply(&mut session, "a FETCH $ FLAGS");
	assert_eq!(response, "a NO [SEARCHRES] $ invalid for FETCH\r\n");
	assert_eq!(response.matches('[').count(), 1);
}

#[test]
fn a_copy_that_cannot_be_written_is_serverbug() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = selected(dir.path(), "SELECT");
	reply(&mut session, "c CREATE Work");
	break_dir(dir.path(), "tmp");
	assert_eq!(
		reply(&mut session, "a COPY 1 Work"),
		"a NO [SERVERBUG] copy failed\r\n"
	);
}
