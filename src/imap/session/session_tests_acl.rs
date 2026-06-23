use super::*;

#[test]
fn myrights_and_getacl_report_owner_full_rights() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let response = text(&session.command_line("a2 MYRIGHTS INBOX"));
	assert!(
		response.contains("* MYRIGHTS \"INBOX\" lrswipkxtea"),
		"{response}"
	);
	assert!(response.contains("a2 OK MYRIGHTS completed"), "{response}");

	let response = text(&session.command_line("a3 GETACL INBOX"));
	assert!(
		response.contains("* ACL \"INBOX\" \"alice\" lrswipkxtea"),
		"{response}"
	);
}

#[test]
fn setacl_then_getacl_then_deleteacl() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Shared");

	// Grant bob read+lookup+seen.
	let response = text(&session.command_line("a3 SETACL Shared bob lrs"));
	assert!(response.contains("a3 OK SETACL completed"), "{response}");

	let response = text(&session.command_line("a4 GETACL Shared"));
	assert!(response.contains("\"bob\" lrs"), "{response}");

	// A `-` modifier removes a right.
	session.command_line("a5 SETACL Shared bob -s");
	let response = text(&session.command_line("a6 GETACL Shared"));
	assert!(response.contains("\"bob\" lr"), "{response}");

	// DELETEACL removes the entry entirely.
	session.command_line("a7 DELETEACL Shared bob");
	let response = text(&session.command_line("a8 GETACL Shared"));
	assert!(!response.contains("bob"), "{response}");
}

#[test]
fn setacl_rejects_invalid_rights() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 SETACL INBOX bob lrZ"));
	assert!(response.contains("a2 BAD"), "{response}");
}

#[test]
fn acl_on_missing_mailbox_is_no() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 GETACL Nope"));
	assert!(response.contains("a2 NO no such mailbox"), "{response}");
}

#[test]
fn listrights_reports_owner_and_other() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 LISTRIGHTS INBOX alice"));
	assert!(
		response.contains("* LISTRIGHTS \"INBOX\" \"alice\" lrswipkxtea"),
		"{response}"
	);
	let response = text(&session.command_line("a3 LISTRIGHTS INBOX bob"));
	assert!(
		response.contains("* LISTRIGHTS \"INBOX\" \"bob\" \"\""),
		"{response}"
	);
}

#[test]
fn acl_owner_rights_are_immutable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// Trying to restrict the owner is a no-op; the owner keeps full rights.
	session.command_line("a2 SETACL INBOX alice lr");
	let response = text(&session.command_line("a3 MYRIGHTS INBOX"));
	assert!(response.contains("lrswipkxtea"), "{response}");
}
