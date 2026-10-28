//! LIST, LSUB, CREATE, DELETE and RENAME over hierarchical mailbox names
//! (RFC 9051 §6.3, RFC 5258, RFC 3348).

use super::super::super::tests::{deliver, logged_in, text};

fn lines(reply: &str, prefix: &str) -> Vec<String> {
	reply
		.lines()
		.filter(|line| line.starts_with(prefix))
		.map(str::to_string)
		.collect()
}

#[test]
fn create_accepts_the_delimiter_and_percent_stops_at_one_level() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let reply = text(&session.command_line(r#"c1 CREATE "Work/Project""#));
	assert_eq!(reply, "c1 OK CREATE completed\r\n");
	let reply = text(&session.command_line(r#"l1 LIST "" "Work%""#));
	assert_eq!(
		reply,
		"* LIST () \"/\" \"Work\"\r\nl1 OK LIST completed\r\n"
	);
	let reply = text(&session.command_line(r#"l2 LIST "Work/" "%""#));
	assert_eq!(
		reply,
		"* LIST () \"/\" \"Work/Project\"\r\nl2 OK LIST completed\r\n"
	);
}

#[test]
fn children_attributes_follow_the_real_tree() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "a/b""#);
	session.command_line(r#"c2 CREATE "ab""#);
	let reply = text(&session.command_line(r#"l1 LIST "" "a*" RETURN (CHILDREN)"#));
	assert_eq!(
		lines(&reply, "* LIST"),
		[
			"* LIST (\\HasChildren) \"/\" \"a\"",
			"* LIST (\\HasNoChildren) \"/\" \"a/b\"",
			"* LIST (\\HasNoChildren) \"/\" \"ab\"",
		]
	);
}

#[test]
fn a_missing_parent_is_listed_as_noselect_with_children() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// Only `a/b` exists, as a store written before superiors were created.
	let folder = dir.path().join("accounts/alice/folders/a&AC8-b/new");
	std::fs::create_dir_all(folder).expect("folder");
	let reply = text(&session.command_line(r#"l1 LIST "" "a%""#));
	assert_eq!(
		reply,
		"* LIST (\\Noselect \\HasChildren) \"/\" \"a\"\r\nl1 OK LIST completed\r\n"
	);
	let reply = text(&session.command_line(r#"l2 LIST () "" "a%""#));
	assert_eq!(
		reply, "* LIST (\\NonExistent \\HasChildren) \"/\" \"a\"\r\nl2 OK LIST completed\r\n",
		"LIST-EXTENDED marks the missing level \\NonExistent"
	);
	// `*` reaches `a/b` itself, so the missing level adds nothing.
	let reply = text(&session.command_line(r#"l3 LIST "" "a*""#));
	assert_eq!(reply, "* LIST () \"/\" \"a/b\"\r\nl3 OK LIST completed\r\n");
	let reply = text(&session.command_line(r#"s1 SELECT "a""#));
	assert!(reply.starts_with("s1 NO"), "{reply}");
}

#[test]
fn list_extended_takes_several_patterns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	for name in ["m/t1", "m/t2/t1", "m/t3", "m/t4/t52"] {
		session.command_line(&format!("c CREATE \"{name}\""));
	}
	let reply = text(&session.command_line(r#"l1 LIST "" (m/*2 "m/t3")"#));
	assert_eq!(
		lines(&reply, "* LIST"),
		[
			"* LIST () \"/\" \"m/t2\"",
			"* LIST () \"/\" \"m/t3\"",
			"* LIST () \"/\" \"m/t4/t52\"",
		]
	);
}

#[test]
fn subscribed_selection_reports_a_deleted_mailbox_as_nonexistent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "m/gone""#);
	session.command_line(r#"s1 SUBSCRIBE "m/gone""#);
	session.command_line(r#"d1 DELETE "m/gone""#);
	let reply = text(&session.command_line(r#"l1 LIST (SUBSCRIBED) "" "m/*""#));
	assert_eq!(
		reply,
		"* LIST (\\Subscribed \\NonExistent) \"/\" \"m/gone\"\r\nl1 OK LIST completed\r\n"
	);
}

#[test]
fn recursivematch_reports_childinfo_for_a_hidden_subscribed_child() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "m/t2/t1""#);
	session.command_line(r#"c2 CREATE "m/t7/t7""#);
	session.command_line(r#"s1 SUBSCRIBE "m/t2/t1""#);
	session.command_line(r#"s2 SUBSCRIBE "m/t7/t7""#);
	let reply = text(
		&session
			.command_line(r#"l1 LIST (SUBSCRIBED RECURSIVEMATCH) "" "m/t2%" RETURN (CHILDREN)"#),
	);
	assert_eq!(
		reply,
		"* LIST (\\HasChildren) \"/\" \"m/t2\" (\"CHILDINFO\" (\"SUBSCRIBED\"))\r\n\
		 l1 OK LIST completed\r\n"
	);
	// The subscribed child matches the pattern itself: no CHILDINFO parent.
	let reply = text(&session.command_line(r#"l2 LIST (SUBSCRIBED RECURSIVEMATCH) "" "m*t7""#));
	assert_eq!(
		reply,
		"* LIST (\\Subscribed) \"/\" \"m/t7/t7\"\r\nl2 OK LIST completed\r\n"
	);
}

#[test]
fn recursivematch_needs_another_selection_option() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	for command in [
		r#"b1 LIST (RECURSIVEMATCH) "" "*""#,
		r#"b2 LIST (RECURSIVEMATCH REMOTE) "" "*""#,
		r#"b3 LIST (IMAPTEST) "" "*""#,
		r#"b4 LIST "" "*" RETURN (IMAPTEST)"#,
	] {
		let reply = text(&session.command_line(command));
		assert!(reply.contains(" BAD "), "{command}: {reply}");
	}
	let reply = text(&session.command_line(r#"l1 LIST (REMOTE) "" "%""#));
	assert!(reply.ends_with("l1 OK LIST completed\r\n"), "{reply}");
}

#[test]
fn lsub_returns_an_unsubscribed_parent_as_noselect() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "m/test""#);
	session.command_line(r#"c2 CREATE "m/test2/test""#);
	session.command_line(r#"s1 SUBSCRIBE "m/test""#);
	session.command_line(r#"s2 SUBSCRIBE "m/test2/test""#);
	let reply = text(&session.command_line(r#"l1 LSUB "" "m/%""#));
	assert_eq!(
		reply,
		"* LSUB () \"/\" \"m/test\"\r\n* LSUB (\\Noselect) \"/\" \"m/test2\"\r\nl1 OK LSUB completed\r\n"
	);
	let reply = text(&session.command_line(r#"l2 LSUB "" "m/*""#));
	assert_eq!(
		lines(&reply, "* LSUB"),
		[
			"* LSUB () \"/\" \"m/test\"",
			"* LSUB () \"/\" \"m/test2/test\""
		]
	);
}

#[test]
fn delete_with_children_answers_haschildren() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "a/b""#);
	let reply = text(&session.command_line(r#"d1 DELETE "a""#));
	assert!(reply.starts_with("d1 NO [HASCHILDREN] "), "{reply}");
	let reply = text(&session.command_line(r#"d2 DELETE "a/b""#));
	assert_eq!(reply, "d2 OK DELETE completed\r\n");
}

#[test]
fn rename_moves_children_and_mail_stays_reachable() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: one\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "a/b""#);
	session.command_line("s0 SELECT INBOX");
	let reply = text(&session.command_line(r#"m1 MOVE 1 "a/b""#));
	assert!(reply.contains("m1 OK"), "{reply}");
	let reply = text(&session.command_line(r#"r1 RENAME "a" "x/y""#));
	assert_eq!(reply, "r1 OK RENAME completed\r\n");
	let reply = text(&session.command_line(r#"st STATUS "x/y/b" (MESSAGES)"#));
	assert!(
		reply.starts_with("* STATUS \"x/y/b\" (MESSAGES 1)\r\n"),
		"{reply}"
	);
	let reply = text(&session.command_line(r#"r2 RENAME "x" "x/y/z""#));
	assert!(reply.starts_with("r2 NO"), "{reply}");
}

#[test]
fn append_copy_and_select_reach_a_hierarchical_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "Work/Project""#);
	let message = b"Subject: hi\r\n\r\nbody\r\n";
	let reply =
		text(&session.command_line(&format!("a1 APPEND \"Work/Project\" {{{}}}", message.len())));
	assert!(reply.starts_with("+ "), "{reply}");
	let reply = text(&session.literal_done(message));
	assert!(reply.contains("a1 OK"), "{reply}");
	let reply = text(&session.command_line(r#"s1 SELECT "Work/Project""#));
	assert!(reply.contains("* 1 EXISTS"), "{reply}");
	let reply = text(&session.command_line(r#"k1 COPY 1 "Work""#));
	assert!(reply.contains("k1 OK"), "{reply}");
	let reply = text(&session.command_line(r#"st STATUS "Work" (MESSAGES)"#));
	assert!(
		reply.starts_with("* STATUS \"Work\" (MESSAGES 1)"),
		"{reply}"
	);
}

#[test]
fn utf8_names_keep_the_hierarchy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("e1 ENABLE UTF8=ACCEPT");
	let reply = text(&session.command_line("c1 CREATE \"Proyectos/Año\""));
	assert_eq!(reply, "c1 OK CREATE completed\r\n");
	assert!(
		dir.path()
			.join("accounts/alice/folders/Proyectos&AC8-A&APE-o")
			.is_dir()
	);
	let reply = text(&session.command_line(r#"l1 LIST "" "Proyectos/%""#));
	assert!(
		reply.contains("\"/\" \"Proyectos/Año\"\r\n"),
		"the client sees the decoded name: {reply}"
	);
}

#[test]
fn a_subscription_under_the_inbox_is_kept_in_one_spelling() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line(r#"c1 CREATE "INBOX/x""#);
	session.command_line(r#"c2 CREATE "Work""#);
	session.command_line(r#"s1 SUBSCRIBE "inbox/x""#);
	session.command_line(r#"s2 SUBSCRIBE "Work""#);
	let reply = text(&session.command_line(r#"l1 LIST (SUBSCRIBED) "" "*""#));
	assert_eq!(
		lines(&reply, "* LIST"),
		[
			"* LIST (\\Subscribed) \"/\" \"INBOX\"",
			"* LIST (\\Subscribed) \"/\" \"INBOX/x\"",
			"* LIST (\\Subscribed) \"/\" \"Work\"",
		]
	);
	// Only INBOX is matched in any case; `work` is another name.
	session.command_line(r#"u1 UNSUBSCRIBE "work""#);
	session.command_line(r#"u2 UNSUBSCRIBE "INBOX/x""#);
	let reply = text(&session.command_line(r#"l2 LSUB "" "*""#));
	assert_eq!(
		lines(&reply, "* LSUB"),
		["* LSUB () \"/\" \"INBOX\"", "* LSUB () \"/\" \"Work\""]
	);
}

#[test]
fn multisearch_subtree_reaches_nested_folders_and_subtree_one_stops_a_level_down() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = crate::storage::MessageCrypto::disabled();
	for name in ["Work", "Work/Project", "Work/Project/Deep"] {
		crate::imap::mailbox::create(dir.path(), "alice", name).expect("create");
		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			name,
			&[],
			b"Subject: x\r\n\r\nx\r\n",
			&crypto,
		)
		.expect("append");
	}
	let mut session = logged_in(dir.path());
	let response =
		text(&session.command_line("m1 ESEARCH IN (subtree (\"Work\")) RETURN (COUNT) ALL"));
	for name in ["Work", "Work/Project", "Work/Project/Deep"] {
		assert!(
			response.contains(&format!("MAILBOX \"{name}\" UIDVALIDITY")),
			"{name} in {response}"
		);
	}
	let response =
		text(&session.command_line("m2 ESEARCH IN (subtree-one (\"Work\")) RETURN (COUNT) ALL"));
	assert!(
		response.contains("MAILBOX \"Work/Project\" UIDVALIDITY"),
		"{response}"
	);
	assert!(!response.contains("Work/Project/Deep"), "{response}");
}
