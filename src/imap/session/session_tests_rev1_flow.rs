use super::*;

#[test]
fn rev1_imaplib_style_flow_and_rev2_equivalent() {
	const BODY: &[u8] = b"Subject: fixture\r\n\r\nmessage\r\n";
	for rev2 in [false, true] {
		for sasl in [false, true] {
			let dir = tempfile::tempdir().expect("tempdir");
			deliver(dir.path(), BODY);
			let mut session =
				Session::new("mail.example.org", dir.path().to_path_buf(), directory());
			assert!(
				text(&session.greeting()).contains("[CAPABILITY IMAP4rev1 IMAP4rev2 "),
				"greeting must admit legacy clients"
			);
			assert!(
				text(&session.command_line("c CAPABILITY"))
					.split_ascii_whitespace()
					.any(|c| c == "IMAP4rev1"),
				"CAPABILITY must satisfy imaplib's revision check"
			);
			if sasl {
				let continuation = session.command_line("a AUTHENTICATE PLAIN");
				assert!(
					continuation.collect_auth,
					"AUTHENTICATE must request a SASL response"
				);
				assert_eq!(text(&continuation), "+ \r\n");
				assert_eq!(
					text(&session.auth_response("AGFsaWNlAHNlY3JldA==")),
					"a OK AUTHENTICATE completed\r\n"
				);
			} else {
				assert_eq!(
					text(&session.command_line("a LOGIN alice secret")),
					"a OK LOGIN completed\r\n"
				);
			}
			if rev2 {
				assert_eq!(
					text(&session.command_line("e ENABLE IMAP4rev2")),
					"* ENABLED IMAP4rev2\r\ne OK ENABLE completed\r\n"
				);
			}
			let selection = text(&session.command_line("s SELECT INBOX"));
			assert!(
				selection.starts_with("* 1 EXISTS\r\n"),
				"SELECT must report the message count"
			);
			assert!(
				selection.ends_with("s OK [READ-WRITE] SELECT completed\r\n"),
				"SELECT must enter read-write state"
			);
			assert!(
				selection.contains("* 0 RECENT\r\n") != rev2,
				"SELECT must use negotiated RECENT behavior"
			);
			let expected = if rev2 {
				"* ESEARCH (TAG \"q\") ALL 1\r\nq OK SEARCH completed\r\n"
			} else {
				"* SEARCH 1\r\nq OK SEARCH completed\r\n"
			};
			assert_eq!(text(&session.command_line("q SEARCH ALL")), expected);
			let expected = format!(
				"* 1 FETCH (UID 1 BODY[] {{{}}}\r\n{} FLAGS (\\Seen))\r\nf OK FETCH completed\r\n",
				BODY.len(),
				String::from_utf8_lossy(BODY)
			);
			assert!(
				session.command_line("f FETCH 1 (UID BODY[])").bytes == expected.as_bytes(),
				"FETCH must preserve the literal byte count and complete body"
			);
			let logout = session.command_line("l LOGOUT");
			assert_eq!(
				text(&logout),
				"* BYE logging out\r\nl OK LOGOUT completed\r\n"
			);
			assert!(logout.close, "LOGOUT must close the connection");
		}
	}
}

#[test]
fn rev1_lsub_and_fetch_move_unselect_extensions_remain_available() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"Content-Transfer-Encoding: base64\r\n\r\nb25l");
		let mut session = logged_in(dir.path());
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		session.command_line("c CREATE Sent");
		session.command_line("s SUBSCRIBE Sent");
		assert_eq!(
			text(&session.command_line(r#"l LSUB "" "Sent""#)),
			"* LSUB () \"/\" \"Sent\"\r\nl OK LSUB completed\r\n"
		);
		session.command_line("u UNSUBSCRIBE Sent");
		assert_eq!(
			text(&session.command_line(r#"l LSUB "" "Sent""#)),
			"l OK LSUB completed\r\n"
		);
		session.command_line("s SELECT INBOX");
		assert!(
			text(&session.command_line("b FETCH 1 (BINARY[] BINARY.SIZE[])"))
				== "* 1 FETCH (BINARY[] {3}\r\none BINARY.SIZE[] 3 FLAGS (\\Seen))\r\nb OK FETCH completed\r\n",
			"BINARY must preserve decoded bytes and size in both revisions"
		);
		let moved = text(&session.command_line("m UID MOVE 1 Sent"));
		assert!(
			moved.starts_with("* 1 EXPUNGE\r\nm OK [COPYUID "),
			"UID MOVE must expunge and report COPYUID"
		);
		assert!(
			moved.ends_with(" 1 1] MOVE completed\r\n"),
			"UID MOVE must report source and destination UIDs"
		);
		assert_eq!(
			text(&session.command_line("q SEARCH RETURN (COUNT) ALL")),
			"* ESEARCH (TAG \"q\") COUNT 0\r\nq OK SEARCH completed\r\n"
		);
		assert_eq!(
			text(&session.command_line("u UNSELECT")),
			"u OK UNSELECT completed\r\n"
		);
		session.command_line("s SELECT Sent");
		assert_eq!(
			text(&session.command_line("f UID FETCH 1 (FLAGS)")),
			"* 1 FETCH (FLAGS (\\Seen) UID 1)\r\nf OK FETCH completed\r\n"
		);
	}
}
