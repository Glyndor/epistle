use super::*;

#[test]
fn rev1_search_response_changes_only_after_enable() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"first\r\n");
	deliver(dir.path(), b"second\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("s SELECT INBOX");
	session.command_line(r"d STORE 1 +FLAGS (\Deleted)");
	session.command_line("x EXPUNGE");
	for rev2 in [false, true] {
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		for (command, hits, marker) in [
			("q SEARCH ALL", "1", ""),
			("q UID SEARCH ALL", "2", " UID"),
			("q SEARCH DELETED", "", ""),
		] {
			let expected = if rev2 {
				let all = if hits.is_empty() {
					String::new()
				} else {
					format!(" ALL {hits}")
				};
				format!("* ESEARCH (TAG \"q\"){marker}{all}\r\nq OK SEARCH completed\r\n")
			} else {
				let suffix = if hits.is_empty() {
					String::new()
				} else {
					format!(" {hits}")
				};
				format!("* SEARCH{suffix}\r\nq OK SEARCH completed\r\n")
			};
			assert!(
				text(&session.command_line(command)) == expected,
				"SEARCH must return the negotiated revision's exact result line"
			);
		}
		assert_eq!(
			text(&session.command_line("r SEARCH RETURN (COUNT) ALL")),
			"* ESEARCH (TAG \"r\") COUNT 1\r\nr OK SEARCH completed\r\n"
		);
		assert_eq!(
			text(&session.command_line("r UID SEARCH RETURN () ALL")),
			"* ESEARCH (TAG \"r\") UID ALL 2\r\nr OK SEARCH completed\r\n"
		);
		session.command_line("u UNSELECT");
		session.command_line("s SELECT INBOX");
	}
}
