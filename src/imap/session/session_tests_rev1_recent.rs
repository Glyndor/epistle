use super::*;

#[test]
fn rev1_recent_selection_metadata_and_status() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"first\r\n");
		deliver(dir.path(), b"second\r\n");
		let mut session = logged_in(dir.path());
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		session.command_line("s SELECT INBOX");
		session.command_line(r"f STORE 1 +FLAGS (\Seen)");
		for verb in ["SELECT", "EXAMINE"] {
			let response = text(&session.command_line(&format!("s {verb} INBOX")));
			assert!(
				response.contains("* 0 RECENT\r\n") != rev2,
				"selection must report zero RECENT only in rev1 mode"
			);
			assert!(
				response.contains("* OK [UNSEEN 2] first unseen message\r\n") != rev2,
				"selection must report first unseen sequence only in rev1 mode"
			);
			assert!(
				!response.contains("\\Recent"),
				"zero recent policy must not advertise a settable Recent flag"
			);
			assert_eq!(
				text(&session.command_line("f FETCH 1:2 (FLAGS)")),
				"* 1 FETCH (FLAGS (\\Seen))\r\n* 2 FETCH (FLAGS ())\r\nf OK FETCH completed\r\n"
			);
			assert_eq!(
				text(&session.command_line("t STATUS INBOX (MESSAGES RECENT)")),
				"* STATUS \"INBOX\" (MESSAGES 2 RECENT 0)\r\nt OK STATUS completed\r\n"
			);
		}
	}
}

#[test]
fn rev1_recent_search_keys_follow_zero_policy() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"first\r\n");
	deliver(dir.path(), b"second\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("s SELECT INBOX");
	session.command_line(r"f STORE 1 +FLAGS (\Seen)");
	for criteria in ["RECENT", "NEW", "OR RECENT NEW", "(NEW UNSEEN)"] {
		assert!(
			text(&session.command_line(&format!("q SEARCH {criteria}")))
				== "* SEARCH\r\nq OK SEARCH completed\r\n",
			"recent and new searches must return an empty legacy result"
		);
	}
	assert_eq!(
		text(&session.command_line("q SEARCH OLD")),
		"* SEARCH 1 2\r\nq OK SEARCH completed\r\n"
	);
	assert_eq!(
		text(&session.command_line("q SEARCH OLD UNSEEN")),
		"* SEARCH 2\r\nq OK SEARCH completed\r\n"
	);
	session.command_line("e ENABLE IMAP4rev2");
	for criteria in ["RECENT", "NEW", "OLD", "NOT RECENT", "OR NEW ALL"] {
		assert_eq!(
			text(&session.command_line(&format!("q SEARCH {criteria}"))),
			"q BAD invalid arguments\r\n"
		);
	}
}

#[test]
fn rev1_unseen_selection_reports_sequence() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"first\r\n");
	deliver(dir.path(), b"second\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("s SELECT INBOX");
	session.command_line(r"f STORE 1 +FLAGS (\Seen)");
	for verb in ["SELECT", "EXAMINE"] {
		let response = text(&session.command_line(&format!("s {verb} INBOX")));
		assert!(
			response.contains("* OK [UNSEEN 2] first unseen message\r\n"),
			"rev1 selection must identify the first unseen sequence"
		);
	}
}
