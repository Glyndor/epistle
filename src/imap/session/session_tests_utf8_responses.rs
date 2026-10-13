//! Every response that carries a mailbox name spells it for the
//! connection: UTF-8 once the client enabled `UTF8=ACCEPT` (RFC 6855 §3),
//! modified UTF-7 otherwise, always as a quoted string.

use super::*;

/// The untagged lines naming the test mailbox (the default ones are left
/// out), in command order.
fn naming_lines(session: &mut Session, name: &str) -> Vec<String> {
	let commands = [
		"LIST \"\" \"*\"".to_string(),
		"LIST \"\" \"*\" RETURN (STATUS (MESSAGES))".to_string(),
		"LSUB \"\" \"*\"".to_string(),
		format!("STATUS \"{name}\" (MESSAGES)"),
		format!("GETACL \"{name}\""),
		format!("MYRIGHTS \"{name}\""),
		format!("LISTRIGHTS \"{name}\" bob"),
		format!("GETMETADATA \"{name}\" /private/comment"),
		format!("ESEARCH IN (mailboxes (\"{name}\")) RETURN (COUNT) ALL"),
		format!("GETQUOTAROOT \"{name}\""),
	];
	let mut lines = Vec::new();
	for (index, command) in commands.iter().enumerate() {
		let tag = format!("n{index}");
		let response = text(&session.command_line(&format!("{tag} {command}")));
		assert!(
			response.contains(&format!("{tag} OK ")),
			"{command}: {response}"
		);
		lines.extend(
			response
				.lines()
				.filter(|line| line.starts_with("* ") && line.contains(" Box\""))
				.map(|line| {
					// Drop the counters and rights: only the name is under test.
					let cut = line
						.find(" (MESSAGES")
						.or_else(|| line.find(" UIDVALIDITY"));
					cut.map_or(line, |at| &line[..at]).to_string()
				}),
		);
	}
	lines
}

fn expected(quoted: &str) -> Vec<String> {
	[
		format!("* LIST () \"/\" {quoted}"),
		format!("* LIST () \"/\" {quoted}"),
		format!("* STATUS {quoted}"),
		format!("* LSUB () \"/\" {quoted}"),
		format!("* STATUS {quoted}"),
		format!("* ACL {quoted} \"alice\" lrswipkxtea"),
		format!("* MYRIGHTS {quoted} lrswipkxtea"),
		format!("* LISTRIGHTS {quoted} \"bob\" \"\" l r s w i p k x t e a"),
		format!("* METADATA {quoted} (\"/private/comment\" {{2}}"),
		format!("* ESEARCH (TAG \"n8\" MAILBOX {quoted}"),
		format!("* QUOTAROOT {quoted} \"\""),
	]
	.into_iter()
	.collect()
}

#[test]
fn utf8_and_rev1_sessions_each_get_their_own_spelling_everywhere() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut utf8 = logged_in(dir.path());
	let enabled = text(&utf8.command_line("e1 ENABLE UTF8=ACCEPT"));
	assert_eq!(
		enabled,
		"* ENABLED UTF8=ACCEPT\r\ne1 OK ENABLE completed\r\n"
	);
	for (tag, command) in [
		("c1", "CREATE \"Café Box\""),
		("c2", "SUBSCRIBE \"Café Box\""),
		("c3", "SETMETADATA \"Café Box\" (/private/comment \"hi\")"),
	] {
		let response = text(&utf8.command_line(&format!("{tag} {command}")));
		assert!(
			response.starts_with(&format!("{tag} OK ")),
			"{command}: {response}"
		);
	}
	assert_eq!(
		naming_lines(&mut utf8, "Café Box"),
		expected("\"Café Box\"")
	);

	let mut rev1 = logged_in(dir.path());
	assert_eq!(
		naming_lines(&mut rev1, "Caf&AOk- Box"),
		expected("\"Caf&AOk- Box\"")
	);
}
