use super::*;

#[test]
fn rev1_list_plain_omits_extension_attributes() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		session.command_line("c CREATE Sent");
		session.command_line("s SUBSCRIBE Sent");
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		let attrs = if rev2 {
			r"\Sent \Subscribed \HasNoChildren"
		} else {
			""
		};
		let expected = format!("* LIST ({attrs}) \"/\" \"Sent\"\r\nl OK LIST completed\r\n");
		assert!(
			text(&session.command_line(r#"l LIST "" "Sent""#)) == expected,
			"plain LIST must emit only the negotiated revision's attributes"
		);
		assert_eq!(
			text(&session.command_line(r#"l LIST "" "Sent" RETURN (STATUS (MESSAGES))"#)),
			format!(
				"* LIST ({attrs}) \"/\" \"Sent\"\r\n* STATUS \"Sent\" (MESSAGES 0)\r\nl OK LIST completed\r\n"
			)
		);
	}
}

#[test]
fn rev1_list_explicit_return_attributes_are_honored() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		session.command_line("c CREATE Sent");
		session.command_line("s SUBSCRIBE Sent");
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		for (modifier, attrs) in [
			("RETURN (CHILDREN)", r"\HasNoChildren"),
			("RETURN (SUBSCRIBED)", r"\Subscribed"),
			("RETURN (SPECIAL-USE)", r"\Sent"),
			("rEtUrN (cHiLdReN)", r"\HasNoChildren"),
		] {
			let attrs = if rev2 {
				r"\Sent \Subscribed \HasNoChildren"
			} else {
				attrs
			};
			let expected = format!("* LIST ({attrs}) \"/\" \"Sent\"\r\nl OK LIST completed\r\n");
			assert!(
				text(&session.command_line(&format!("l LIST \"\" \"Sent\" {modifier}")))
					== expected,
				"LIST RETURN must honor the requested attributes"
			);
		}
		for (selection, attrs) in [
			("SUBSCRIBED", r"\Subscribed"),
			("CHILDREN", r"\HasNoChildren"),
		] {
			let attrs = if rev2 {
				r"\Sent \Subscribed \HasNoChildren"
			} else {
				attrs
			};
			assert_eq!(
				text(&session.command_line(&format!("l LIST ({selection}) \"\" \"Sent\""))),
				format!("* LIST ({attrs}) \"/\" \"Sent\"\r\nl OK LIST completed\r\n")
			);
		}
		assert_eq!(
			text(&session.command_line(
				r#"l LIST "" "Sent" RETURN (SPECIAL-USE SUBSCRIBED CHILDREN STATUS (MESSAGES RECENT))"#
			)),
			"* LIST (\\Sent \\Subscribed \\HasNoChildren) \"/\" \"Sent\"\r\n* STATUS \"Sent\" (MESSAGES 0 RECENT 0)\r\nl OK LIST completed\r\n"
		);
		assert_eq!(
			text(&session.command_line(r#"l LIST "" "Sent" RETURN (BOGUS)"#)),
			"l BAD invalid arguments\r\n"
		);
	}
}
