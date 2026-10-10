use super::*;

#[test]
fn rev1_capability_advertises_both_revisions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let greeting = text(&session.greeting());
	assert!(
		greeting.contains("[CAPABILITY IMAP4rev1 IMAP4rev2 "),
		"greeting must advertise both revisions"
	);
	for command in [
		"c CAPABILITY",
		"l LOGIN alice secret",
		"c CAPABILITY",
		"e ENABLE IMAP4rev2",
		"c CAPABILITY",
	] {
		let response = text(&session.command_line(command));
		if command.ends_with("CAPABILITY") {
			assert!(
				response.starts_with("* CAPABILITY IMAP4rev1 IMAP4rev2 "),
				"CAPABILITY must advertise both revisions before and after authentication"
			);
		}
	}
}

#[test]
fn rev1_enable_retains_revision_for_connection() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	assert!(
		!session.rev2_enabled(),
		"new connections must start in rev1 mode"
	);
	assert_eq!(
		text(&session.command_line("e ENABLE IMAP4rev2")),
		"e BAD ENABLE only after authentication\r\n"
	);
	assert!(
		!session.rev2_enabled(),
		"rejected ENABLE must leave rev1 mode active"
	);
	session.command_line("l LOGIN alice secret");
	session.command_line("e ENABLE BOGUS CONDSTORE");
	assert!(
		!session.rev2_enabled(),
		"other capabilities must leave rev1 mode active"
	);
	assert_eq!(
		text(&session.command_line("e ENABLE imap4rev2")),
		"* ENABLED IMAP4rev2\r\ne OK ENABLE completed\r\n"
	);
	assert!(
		session.rev2_enabled(),
		"ENABLE IMAP4rev2 must retain the revision"
	);
	session.command_line("s SELECT INBOX");
	session.command_line("u UNSELECT");
	session.command_line("e ENABLE CONDSTORE");
	assert!(
		session.rev2_enabled(),
		"revision must survive selection and subsequent ENABLE"
	);
}
