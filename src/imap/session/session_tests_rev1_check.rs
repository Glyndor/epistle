use super::*;

#[test]
fn rev1_check_completes_without_changing_selection() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"body\r\n");
		let mut session = logged_in(dir.path());
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		for verb in ["SELECT", "EXAMINE"] {
			session.command_line(&format!("s {verb} INBOX"));
			assert!(
				text(&session.command_line("c CHECK")) == "c OK CHECK completed\r\n",
				"selected CHECK must complete with a tagged OK"
			);
			assert_eq!(
				text(&session.command_line("f UID FETCH 1 (FLAGS)")),
				"* 1 FETCH (FLAGS () UID 1)\r\nf OK FETCH completed\r\n"
			);
		}
		session.command_line("u UNSELECT");
		assert_eq!(
			text(&session.command_line("c CHECK")),
			"c BAD no mailbox selected\r\n"
		);
		assert_eq!(
			text(&session.command_line("c CHECK extra")),
			"c BAD invalid arguments\r\n"
		);
	}
}

#[test]
fn rev1_check_requires_selection() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	assert!(
		text(&session.command_line("c CHECK")) == "c BAD no mailbox selected\r\n",
		"CHECK before authentication must report missing selection"
	);
}
