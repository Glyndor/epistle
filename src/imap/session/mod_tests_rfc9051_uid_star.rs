use super::*;

fn shifted_mailbox() -> (tempfile::TempDir, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	for _ in 0..3 {
		deliver(dir.path(), b"Subject: survivor\r\n\r\nbody\r\n");
	}
	let mut session = logged_in(dir.path());
	session.command_line("a1 SELECT INBOX");
	session.command_line(r"a2 STORE 1 +FLAGS (\Deleted)");
	assert_eq!(
		text(&session.command_line("a3 EXPUNGE")),
		"* 1 EXPUNGE\r\na3 OK EXPUNGE completed\r\n"
	);
	(dir, session)
}

fn assert_survivors(session: &mut Session) {
	assert_eq!(
		text(&session.command_line("v UID SEARCH ALL")),
		"* SEARCH 2 3\r\nv OK SEARCH completed\r\n",
		"the surviving mailbox must retain UIDs 2 and 3"
	);
}

#[test]
fn uid_fetch_star_returns_highest_uid_after_expunge() {
	let (_dir, mut session) = shifted_mailbox();
	assert_eq!(
		text(&session.command_line("q UID FETCH * (UID)")),
		"* 2 FETCH (UID 3)\r\nq OK FETCH completed\r\n",
		"UID FETCH star must return the highest UID at its current sequence number"
	);
	assert_eq!(
		text(&session.command_line("q FETCH * (UID)")),
		"* 2 FETCH (UID 3)\r\nq OK FETCH completed\r\n"
	);
	assert_survivors(&mut session);
}

#[test]
fn uid_store_star_targets_highest_uid_after_expunge() {
	let (dir, mut session) = shifted_mailbox();
	assert_eq!(
		text(&session.command_line(r"q UID STORE * +FLAGS (\Flagged)")),
		"* 2 FETCH (UID 3 FLAGS (\\Flagged))\r\nq OK STORE completed\r\n",
		"UID STORE star must flag only the highest UID"
	);
	let mut reopened = logged_in(dir.path());
	reopened.command_line("a SELECT INBOX");
	assert_eq!(
		text(&reopened.command_line("v UID FETCH 2:3 (UID FLAGS)")),
		"* 1 FETCH (UID 2 FLAGS ())\r\n* 2 FETCH (UID 3 FLAGS (\\Flagged))\r\nv OK FETCH completed\r\n",
		"only UID 3 must have the persisted flag"
	);
}

#[test]
fn search_uid_star_uses_uid_maximum_in_nested_criteria() {
	let (_dir, mut session) = shifted_mailbox();
	for command in [
		"q SEARCH UID *",
		"q SEARCH OR UID * NOT ALL",
		"q SEARCH (UID *)",
		"q UID SEARCH UID *",
	] {
		let hit = if command.starts_with("q UID") { 3 } else { 2 };
		assert_eq!(
			text(&session.command_line(command)),
			format!("* SEARCH {hit}\r\nq OK SEARCH completed\r\n"),
			"UID search criteria must resolve star to the highest UID"
		);
	}
	assert_eq!(
		text(&session.command_line("q UID SEARCH *")),
		"* SEARCH 3\r\nq OK SEARCH completed\r\n",
		"a sequence criterion in UID SEARCH must still use message count"
	);
	assert_survivors(&mut session);
}

#[test]
fn sort_and_thread_uid_criteria_use_uid_maximum() {
	let (_dir, mut session) = shifted_mailbox();
	for (command, expected) in [
		(
			"q SORT (ARRIVAL) UTF-8 UID *",
			"* SORT 2\r\nq OK SORT completed\r\n",
		),
		(
			"q UID SORT (ARRIVAL) UTF-8 UID *",
			"* SORT 3\r\nq OK SORT completed\r\n",
		),
		(
			"q UID SORT (ARRIVAL) UTF-8 *",
			"* SORT 3\r\nq OK SORT completed\r\n",
		),
		(
			"q THREAD ORDEREDSUBJECT UTF-8 UID *",
			"* THREAD (2)\r\nq OK THREAD completed\r\n",
		),
		(
			"q UID THREAD ORDEREDSUBJECT UTF-8 UID *",
			"* THREAD (3)\r\nq OK THREAD completed\r\n",
		),
		(
			"q UID THREAD ORDEREDSUBJECT UTF-8 *",
			"* THREAD (3)\r\nq OK THREAD completed\r\n",
		),
	] {
		assert_eq!(
			text(&session.command_line(command)),
			expected,
			"SORT and THREAD must distinguish UID and sequence maxima"
		);
	}
	assert_survivors(&mut session);
}

#[test]
fn esearch_uid_star_uses_uid_maximum() {
	let (_dir, mut session) = shifted_mailbox();
	let response = text(&session.command_line("q ESEARCH IN (selected) RETURN (ALL) UID *"));
	assert!(
		response.contains(" UID ALL 3\r\n"),
		"ESEARCH UID star must report exactly UID 3"
	);
	assert_survivors(&mut session);
}

#[test]
fn uid_copy_and_move_star_target_highest_uid() {
	for verb in ["COPY", "MOVE"] {
		let (dir, mut session) = shifted_mailbox();
		session.command_line("a CREATE Archive");
		let response = text(&session.command_line(&format!("q UID {verb} * Archive")));
		assert!(
			response.contains(&format!("{verb} completed\r\n")),
			"UID copy or move must complete"
		);
		let mut destination = logged_in(dir.path());
		destination.command_line("a SELECT Archive");
		assert_eq!(
			text(&destination.command_line("v SEARCH ALL")),
			"* SEARCH 1\r\nv OK SEARCH completed\r\n",
			"UID star must transfer exactly one message"
		);
		if verb == "MOVE" {
			assert_eq!(
				text(&session.command_line("v UID SEARCH ALL")),
				"* SEARCH 2\r\nv OK SEARCH completed\r\n",
				"UID MOVE star must remove UID 3 and retain UID 2"
			);
		} else {
			assert!(
				response.contains(" 3 1]"),
				"COPYUID must identify UID 3 as the source"
			);
			assert_survivors(&mut session);
		}
	}
}

#[test]
fn uid_star_on_empty_mailbox_matches_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a SELECT INBOX");
	assert_eq!(
		text(&session.command_line("q UID FETCH * (UID)")),
		"q OK FETCH completed\r\n"
	);
	assert_eq!(
		text(&session.command_line("q SEARCH UID *")),
		"* SEARCH\r\nq OK SEARCH completed\r\n"
	);
	assert_eq!(
		text(&session.command_line("q UID SEARCH ALL")),
		"* SEARCH\r\nq OK SEARCH completed\r\n"
	);
}
