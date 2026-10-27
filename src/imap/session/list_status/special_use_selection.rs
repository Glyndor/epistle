use super::super::tests::{logged_in, text};

fn selected_defaults(rev2: bool) -> String {
	let mut response = String::new();
	for (name, role) in [
		("Archive", "\\Archive"),
		("Drafts", "\\Drafts"),
		("Rejects", "\\Junk"),
		("Sent", "\\Sent"),
		("Trash", "\\Trash"),
	] {
		let children = if rev2 { " \\HasNoChildren" } else { "" };
		response.push_str(&format!("* LIST ({role}{children}) \"/\" \"{name}\"\r\n"));
	}
	response.push_str("l OK LIST completed\r\n");
	response
}

#[test]
fn special_use_selection_lists_only_roles_with_exact_attributes_and_patterns() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		session.command_line("c CREATE Projects");
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		for options in ["SPECIAL-USE", "sPeCiAl-UsE"] {
			for pattern in ["*", "%"] {
				let output =
					session.command_line(&format!("l LIST ({options}) \"\" \"{pattern}\""));
				assert!(
					text(&output) == selected_defaults(rev2),
					"SPECIAL-USE selection must return only the five role mailboxes with exact attributes"
				);
			}
		}
		for name in ["INBOX", "Projects"] {
			assert!(
				text(&session.command_line(&format!("l LIST (SPECIAL-USE) \"\" \"{name}\"")))
					== "l OK LIST completed\r\n",
				"SPECIAL-USE selection must exclude matching mailboxes without a role"
			);
		}
		let children = if rev2 { " \\HasNoChildren" } else { "" };
		assert!(
			text(&session.command_line(r#"l LIST (SPECIAL-USE) "" "Sent""#))
				== format!("* LIST (\\Sent{children}) \"/\" \"Sent\"\r\nl OK LIST completed\r\n"),
			"SPECIAL-USE selection must retain the mailbox pattern"
		);
	}
}

#[test]
fn special_use_selection_intersects_subscribed_and_preserves_return_status() {
	for rev2 in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		session.command_line("c CREATE Projects");
		for name in ["Sent", "Archive", "Projects"] {
			session.command_line(&format!("s SUBSCRIBE {name}"));
		}
		if rev2 {
			session.command_line("e ENABLE IMAP4rev2");
		}
		let expected = concat!(
			"* LIST (\\Archive \\Subscribed \\HasNoChildren) \"/\" \"Archive\"\r\n",
			"* STATUS \"Archive\" (MESSAGES 0)\r\n",
			"* LIST (\\Sent \\Subscribed \\HasNoChildren) \"/\" \"Sent\"\r\n",
			"* STATUS \"Sent\" (MESSAGES 0)\r\n",
			"l OK LIST completed\r\n",
		);
		for options in [
			"SPECIAL-USE SUBSCRIBED",
			"sUbScRiBeD sPeCiAl-UsE",
			"SPECIAL-USE SUBSCRIBED CHILDREN",
		] {
			let output = session.command_line(&format!(
				"l LIST ({options}) \"\" \"*\" RETURN (CHILDREN STATUS (MESSAGES))"
			));
			assert!(
				text(&output) == expected,
				"SPECIAL-USE and SUBSCRIBED must intersect and retain exact LIST and STATUS responses"
			);
		}
	}
}
