//! The advertised capability list before and after login, and the
//! extensions it promises.

use super::*;

/// The full post-login capability set of a session without client
/// certificates, channel binding or OAuth.
const POST_LOGIN: &str = "* CAPABILITY IMAP4rev1 IMAP4rev2 MOVE IDLE LITERAL+ SPECIAL-USE NAMESPACE \
ID UIDPLUS SORT THREAD=ORDEREDSUBJECT UNSELECT ENABLE ESEARCH MULTISEARCH QUOTA QUOTA=RES-STORAGE \
STATUS=SIZE CONDSTORE LIST-EXTENDED LIST-STATUS BINARY QRESYNC OBJECTID SAVEDATE PREVIEW REPLACE ACL \
RIGHTS=texk METADATA CHILDREN WITHIN SEARCHRES COMPRESS=DEFLATE NOTIFY UIDONLY AUTH=SCRAM-SHA-256 AUTH=PLAIN \
AUTH=LOGIN SASL-IR\r\n";

#[test]
fn post_login_capability_lists_uidonly() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("c1 CAPABILITY"));
	assert_eq!(
		response,
		format!("{POST_LOGIN}c1 OK CAPABILITY completed\r\n")
	);
}

#[test]
fn pre_login_capability_leaves_uidonly_out() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let response = text(&session.command_line("c1 CAPABILITY"));
	assert!(
		response.starts_with("* CAPABILITY IMAP4rev1 "),
		"{response}"
	);
	assert!(!response.contains(" UIDONLY"), "{response}");
}

#[test]
fn enabled_uidonly_refuses_a_sequence_number_fetch() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: one\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	let enabled = text(&session.command_line("e1 ENABLE UIDONLY"));
	assert_eq!(enabled, "* ENABLED UIDONLY\r\ne1 OK ENABLE completed\r\n");
	let selected = text(&session.command_line("s1 SELECT INBOX"));
	assert!(selected.contains("s1 OK"), "{selected}");
	let fetch = text(&session.command_line("f1 FETCH 1 (FLAGS)"));
	assert_eq!(
		fetch,
		"f1 BAD [UIDREQUIRED] FETCH requires UID under UIDONLY\r\n"
	);
	let uid_fetch = text(&session.command_line("f2 UID FETCH 1:* (FLAGS)"));
	assert!(uid_fetch.contains("f2 OK"), "{uid_fetch}");
}
