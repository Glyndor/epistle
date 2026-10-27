//! ACL, METADATA and QUOTA reach a hierarchical mailbox through its one flat
//! directory, and the per-mailbox files move with it on RENAME.

use super::*;

fn folder(dir: &std::path::Path, disk: &str) -> std::path::PathBuf {
	dir.join("accounts/alice/folders").join(disk)
}

#[test]
fn acl_of_a_subfolder_lives_in_its_own_directory_and_follows_a_rename() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "Team/Shared""#);
	let reply = text(&session.command_line(r#"a1 SETACL "Team/Shared" bob lrs"#));
	assert!(reply.contains("a1 OK SETACL completed"), "{reply}");
	assert!(folder(dir.path(), "Team&AC8-Shared").join(".acl").is_file());
	assert!(
		!folder(dir.path(), "Team").join(".acl").exists(),
		"not the parent's"
	);
	session.command_line(r#"r1 RENAME "Team" "Crew""#);
	let reply = text(&session.command_line(r#"a2 GETACL "Crew/Shared""#));
	assert!(reply.contains("\"bob\" lrs"), "{reply}");
}

#[test]
fn metadata_of_a_subfolder_round_trips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "Work/Project""#);
	let reply =
		text(&session.command_line(r#"m1 SETMETADATA "Work/Project" (/private/comment "deep")"#));
	assert!(reply.contains("m1 OK SETMETADATA completed"), "{reply}");
	assert!(
		folder(dir.path(), "Work&AC8-Project")
			.join(".metadata")
			.is_file()
	);
	let reply = text(&session.command_line(r#"m2 GETMETADATA "Work" /private/comment"#));
	assert!(!reply.contains("deep"), "the parent has its own: {reply}");
	let reply = text(&session.command_line(r#"m3 GETMETADATA "Work/Project" /private/comment"#));
	assert!(reply.contains("deep"), "{reply}");
}

#[test]
fn quota_counts_mail_in_a_subfolder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "Work/Project""#);
	let message = b"Subject: hi\r\n\r\nbody\r\n";
	session.command_line(&format!(
		r#"a1 APPEND "Work/Project" {{{}}}"#,
		message.len()
	));
	session.literal_done(message);
	let reply = text(&session.command_line(r#"q1 GETQUOTAROOT "Work/Project""#));
	assert!(
		reply.starts_with("* QUOTAROOT \"Work/Project\" \"\"\r\n"),
		"{reply}"
	);
	let usage = crate::imap::mailbox::account_usage(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
	);
	assert_eq!(usage, message.len() as u64);
}
