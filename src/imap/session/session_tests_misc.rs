use super::*;

#[test]
fn plaintext_session_disables_login_until_starttls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session =
		Session::new("mail.example.org", dir.path().to_path_buf(), directory()).with_starttls();

	let greeting = text(&session.greeting());
	assert!(greeting.contains("STARTTLS"), "{greeting}");
	assert!(greeting.contains("LOGINDISABLED"), "{greeting}");
	assert!(!greeting.contains("AUTH=PLAIN"), "{greeting}");

	let output = session.command_line("a1 LOGIN alice secret");
	assert!(
		text(&output).contains("PRIVACYREQUIRED"),
		"{}",
		text(&output)
	);

	let output = session.command_line("a2 STARTTLS");
	assert!(output.upgrade_tls);
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));

	session.tls_started();
	let output = session.command_line("a3 CAPABILITY");
	let response = text(&output);
	assert!(!response.contains("STARTTLS"), "{response}");
	assert!(response.contains("AUTH=PLAIN"), "{response}");
	let output = session.command_line("a4 LOGIN alice secret");
	assert!(text(&output).contains("a4 OK"), "{}", text(&output));
}

#[test]
fn namespace_returns_personal_namespace() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 NAMESPACE");
	let response = text(&output);
	assert!(
		response.contains("* NAMESPACE ((\"\" \"/\")) NIL NIL"),
		"{response}"
	);
	assert!(response.contains("a1 OK NAMESPACE completed"), "{response}");
}

#[test]
fn id_returns_server_identity_and_accepts_client_params() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 ID (\"name\" \"Thunderbird\" \"version\" \"128\")");
	let response = text(&output);
	assert!(
		response.contains("* ID (\"name\" \"Glyndor\""),
		"{response}"
	);
	assert!(response.contains("a1 OK ID completed"), "{response}");
	// NIL parameter list is also accepted.
	assert!(text(&session.command_line("a2 ID NIL")).contains("a2 OK"));
}

#[test]
fn capability_advertises_namespace_and_special_use() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let response = text(&session.command_line("a1 CAPABILITY"));
	assert!(response.contains("NAMESPACE"), "{response}");
	assert!(response.contains("SPECIAL-USE"), "{response}");
	assert!(response.contains("UNSELECT"), "{response}");
	assert!(response.contains("ENABLE"), "{response}");
}

#[test]
fn quota_reports_storage_usage() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\nsome bytes\r\n");
	let mut session = logged_in(dir.path());

	let response = text(&session.command_line("a2 GETQUOTAROOT INBOX"));
	assert!(response.contains("* QUOTAROOT INBOX \"\""), "{response}");
	assert!(response.contains("* QUOTA \"\" (STORAGE "), "{response}");
	assert!(
		response.contains("a2 OK GETQUOTAROOT completed"),
		"{response}"
	);

	let response = text(&session.command_line("a3 GETQUOTA \"\""));
	assert!(response.contains("STORAGE "), "{response}");
	assert!(response.contains("a3 OK GETQUOTA completed"), "{response}");

	// GETQUOTA requires authentication.
	let mut anon = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	assert!(text(&anon.command_line("b1 GETQUOTA \"\"")).contains("b1 NO"));
}

#[test]
fn append_over_quota_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A tiny 100-byte quota.
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory())
		.with_quota_limit(100);
	// (Authenticate.)
	session.command_line("a1 LOGIN alice secret");
	// A 200-byte APPEND exceeds the quota and is refused before the literal.
	let output = session.command_line("a2 APPEND INBOX {200}");
	let response = text(&output);
	assert!(response.contains("a2 NO [OVERQUOTA]"), "{response}");
	assert_eq!(
		output.collect_literal, None,
		"literal must not be collected"
	);
	// A small APPEND within quota still works.
	let output = session.command_line("a3 APPEND INBOX {10}");
	assert_eq!(output.collect_literal, Some(10));
}

#[test]
fn unselect_leaves_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 UNSELECT"));
	assert!(response.contains("a3 OK UNSELECT completed"), "{response}");
	// No mailbox selected afterwards.
	assert!(
		text(&session.command_line("a4 UNSELECT")).contains("a4 BAD"),
		"second UNSELECT should fail"
	);
}

#[test]
fn enable_acknowledges_capabilities() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 ENABLE IMAP4rev2 BOGUS"));
	assert!(response.contains("* ENABLED IMAP4rev2"), "{response}");
	assert!(response.contains("a2 OK ENABLE completed"), "{response}");
}

#[test]
fn starttls_inside_tls_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 STARTTLS");
	assert!(text(&output).contains("a2 BAD"), "{}", text(&output));
	assert!(!output.upgrade_tls);
}

#[test]
fn logout_closes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 LOGOUT");
	assert!(output.close);
	assert!(text(&output).contains("* BYE"));
}

#[test]
fn examine_is_read_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 EXAMINE INBOX");
	assert!(text(&output).contains("READ-ONLY"));
}

#[test]
fn unknown_mailbox_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 SELECT Archive");
	assert!(text(&output).contains("a2 NO"));
}

#[test]
fn status_reports_counts_for_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());

	let response =
		text(&session.command_line("a2 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN RECENT)"));
	assert!(response.contains("MESSAGES 2"), "{response}");
	assert!(response.contains("UNSEEN 2"), "{response}");
	assert!(response.contains("RECENT 0"), "{response}");
	assert!(response.contains("a2 OK STATUS completed"), "{response}");

	// Mark one seen; UNSEEN should drop to 1.
	session.command_line("a3 SELECT INBOX");
	session.command_line(r"a4 STORE 1 +FLAGS (\Seen)");
	session.command_line("a5 CLOSE");
	let response = text(&session.command_line("a6 STATUS INBOX (MESSAGES UNSEEN)"));
	assert!(response.contains("MESSAGES 2"), "{response}");
	assert!(response.contains("UNSEEN 1"), "{response}");
}

#[test]
fn status_requires_authentication_and_existing_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 STATUS INBOX (MESSAGES)");
	assert!(text(&output).contains("a1 NO"), "{}", text(&output));

	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 STATUS Archive (MESSAGES)");
	assert!(text(&output).contains("a2 NO"), "{}", text(&output));
}

#[test]
fn subscribe_and_lsub_flow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Sent");

	// INBOX always present in LSUB even without explicit SUBSCRIBE.
	let response = text(&session.command_line(r#"a3 LSUB "" "*""#));
	assert!(response.contains("\"INBOX\""), "{response}");
	assert!(response.contains("a3 OK LSUB completed"), "{response}");

	// Subscribe Sent; it must appear.
	let output = session.command_line("a4 SUBSCRIBE Sent");
	assert!(text(&output).contains("a4 OK"), "{}", text(&output));
	let response = text(&session.command_line(r#"a5 LSUB "" "*""#));
	assert!(response.contains("\"Sent\""), "{response}");

	// Unsubscribe Sent; it disappears.
	session.command_line("a6 UNSUBSCRIBE Sent");
	let response = text(&session.command_line(r#"a7 LSUB "" "*""#));
	assert!(!response.contains("\"Sent\""), "{response}");
	assert!(response.contains("\"INBOX\""), "{response}");
}

#[test]
fn internaldate_is_not_epoch() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\nhi\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 FETCH 1 (INTERNALDATE)"));
	// Must not be the epoch placeholder.
	assert!(!response.contains("01-Jan-1970"), "{response}");
	assert!(response.contains("INTERNALDATE"), "{response}");
	assert!(response.contains("a3 OK FETCH completed"), "{response}");
}

#[test]
fn internaldate_format_sanity() {
	// 2024-06-09 12:34:56 UTC = 1717936496 seconds since epoch.
	let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_717_936_496);
	assert_eq!(format_internaldate(t), " 9-Jun-2024 12:34:56 +0000");
	// Epoch itself.
	assert_eq!(
		format_internaldate(std::time::UNIX_EPOCH),
		" 1-Jan-1970 00:00:00 +0000"
	);
	// A date with a two-digit day (no space padding).
	let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_718_000_000);
	let s = format_internaldate(t);
	// 2024-06-10 in UTC; day >= 10 so no leading space.
	assert!(
		!s.starts_with(' '),
		"expected no leading space for day >= 10: {s}"
	);
}
