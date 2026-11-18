use super::super::super::tests::base::{logged_in, text};
use crate::imap::special_use::{Role, roles};

#[test]
fn list_reports_the_role_the_account_recorded_and_not_the_name_it_replaced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("c CREATE Basura");
	roles::set(dir.path(), "alice", Role::Junk, "Basura").expect("record the role");
	let output = text(&session.command_line("l LIST (SPECIAL-USE) \"\" \"*\""));
	assert!(
		output.contains("* LIST (\\Junk) \"/\" \"Basura\"\r\n"),
		"the recorded folder is the spam folder: {output}"
	);
	assert!(
		!output.contains("\"Rejects\""),
		"the name that used to carry the role does not: {output}"
	);
	for kept in ["Sent", "Drafts", "Trash", "Archive"] {
		assert!(output.contains(&format!("\"{kept}\"")), "{kept}: {output}");
	}
}

#[test]
fn an_account_without_a_record_lists_what_it_always_did() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = text(&session.command_line("l LIST (SPECIAL-USE) \"\" \"*\""));
	assert!(
		output.contains("* LIST (\\Junk) \"/\" \"Rejects\"\r\n"),
		"{output}"
	);
}
