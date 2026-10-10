use super::*;

fn sessions() -> (tempfile::TempDir, Session, Session) {
	let dir = tempfile::tempdir().expect("tempdir");
	for _ in 0..5 {
		deliver(dir.path(), b"Subject: message\r\n\r\nbody\r\n");
	}
	let mut observer = logged_in(dir.path());
	let mut writer = logged_in(dir.path());
	observer.command_line("a SELECT INBOX");
	writer.command_line("b SELECT INBOX");
	(dir, observer, writer)
}

fn start(observer: &mut Session, notify: bool) {
	let command = if notify {
		"a NOTIFY SET (selected (MessageNew MessageExpunge))"
	} else {
		"a IDLE"
	};
	let expected = if notify {
		"a OK NOTIFY completed\r\n"
	} else {
		"+ idling\r\n"
	};
	assert_eq!(text(&observer.command_line(command)), expected);
}

fn poll(observer: &mut Session, notify: bool) -> Option<Output> {
	if notify {
		observer.check_notify()
	} else {
		observer.check_idle()
	}
}

fn remove_two(writer: &mut Session) {
	assert_eq!(
		text(&writer.command_line(r"b STORE 2,4 +FLAGS.SILENT (\Deleted)")),
		"b OK STORE completed\r\n"
	);
	assert_eq!(
		text(&writer.command_line("b EXPUNGE")),
		"* 2 EXPUNGE\r\n* 3 EXPUNGE\r\nb OK EXPUNGE completed\r\n"
	);
}

fn assert_remaining(observer: &mut Session, notify: bool, writer: &mut Session) {
	if !notify {
		assert_eq!(text(&observer.idle_done()), "a OK IDLE terminated\r\n");
	}
	assert_eq!(
		text(&observer.command_line("v FETCH 1:* (UID)")),
		"* 1 FETCH (UID 1)\r\n* 2 FETCH (UID 3)\r\n* 3 FETCH (UID 5)\r\nv OK FETCH completed\r\n",
		"the observer must retain the surviving UIDs at their new sequence numbers"
	);
	writer.command_line("b SELECT INBOX");
	assert_eq!(
		text(&writer.command_line("v UID SEARCH ALL")),
		"* SEARCH 1 3 5\r\nv OK SEARCH completed\r\n",
		"the persisted mailbox must retain exactly UIDs 1, 3 and 5"
	);
}

fn expunge_notifications(notify: bool) {
	let (_dir, mut observer, mut writer) = sessions();
	start(&mut observer, notify);
	remove_two(&mut writer);
	let response = poll(&mut observer, notify)
		.map(|o| text(&o))
		.unwrap_or_default();
	assert_eq!(
		response, "* 4 EXPUNGE\r\n* 2 EXPUNGE\r\n",
		"polling must report removed messages in descending sequence order without a lower EXISTS"
	);
	assert_eq!(
		poll(&mut observer, notify).map(|o| text(&o)),
		None,
		"polling must report each removal once"
	);
	assert_remaining(&mut observer, notify, &mut writer);
}

#[test]
fn idle_reports_concurrent_expunges_before_renumbering() {
	expunge_notifications(false);
}

#[test]
fn notify_reports_concurrent_expunges_before_renumbering() {
	expunge_notifications(true);
}

fn replacement_notifications(notify: bool, additions: usize) {
	let (dir, mut observer, mut writer) = sessions();
	start(&mut observer, notify);
	remove_two(&mut writer);
	for _ in 0..additions {
		deliver(dir.path(), b"Subject: new\r\n\r\nbody\r\n");
	}
	let response = poll(&mut observer, notify)
		.map(|o| text(&o))
		.unwrap_or_default();
	assert_eq!(
		response,
		format!(
			"* 4 EXPUNGE\r\n* 2 EXPUNGE\r\n* {} EXISTS\r\n",
			3 + additions
		),
		"expunges must precede arrivals even when the final message count does not grow"
	);
	assert_eq!(poll(&mut observer, notify).map(|o| text(&o)), None);
	if !notify {
		assert_eq!(text(&observer.idle_done()), "a OK IDLE terminated\r\n");
	}
	let expected = if additions == 1 {
		"1 3 5 6"
	} else {
		"1 3 5 6 7"
	};
	assert_eq!(
		text(&observer.command_line("v UID SEARCH ALL")),
		format!("* SEARCH {expected}\r\nv OK SEARCH completed\r\n"),
		"the observer must contain survivors and new UIDs"
	);
	writer.command_line("b SELECT INBOX");
	assert_eq!(
		text(&writer.command_line("v UID SEARCH ALL")),
		format!("* SEARCH {expected}\r\nv OK SEARCH completed\r\n"),
		"the persisted mailbox must match the observer"
	);
}

#[test]
fn idle_reports_expunges_before_exists_when_count_is_unchanged() {
	replacement_notifications(false, 2);
}

#[test]
fn notify_reports_expunges_before_exists_when_count_is_unchanged() {
	replacement_notifications(true, 2);
}

#[test]
fn idle_reports_arrivals_after_expunges_when_final_count_is_lower() {
	replacement_notifications(false, 1);
}

#[test]
fn notify_reports_arrivals_after_expunges_when_final_count_is_lower() {
	replacement_notifications(true, 1);
}

#[test]
fn uidonly_idle_reports_concurrent_removals_as_vanished() {
	let (dir, _observer, mut writer) = sessions();
	let mut observer = logged_in(dir.path());
	observer.command_line("a ENABLE UIDONLY");
	observer.command_line("a SELECT INBOX");
	start(&mut observer, false);
	remove_two(&mut writer);
	assert_eq!(
		observer.check_idle().map(|o| text(&o)).unwrap_or_default(),
		"* VANISHED 2,4\r\n",
		"UIDONLY polling must identify removed UIDs with VANISHED"
	);
	assert_eq!(text(&observer.idle_done()), "a OK IDLE terminated\r\n");
	assert_eq!(
		text(&observer.command_line("v UID SEARCH ALL")),
		"* SEARCH 1 3 5\r\nv OK SEARCH completed\r\n"
	);
}
