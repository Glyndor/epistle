use super::*;

#[test]
fn clean_store_reports_no_problems() {
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[Flag::Seen],
		b"Subject: x\r\n\r\nbody",
		&MessageCrypto::disabled(),
	)
	.expect("append");
	mailbox::append(
		dir.path(),
		"alice",
		"Archive",
		&[],
		b"Subject: y\r\n\r\nbody",
		&MessageCrypto::disabled(),
	)
	.expect("append");
	let mut out = Vec::new();
	assert_eq!(
		run(dir.path(), &MessageCrypto::disabled(), false, &mut out),
		ExitCode::SUCCESS
	);
	let report = String::from_utf8(out).expect("utf8");
	assert!(report.contains("2 messages: 0 problems"), "{report}");
}

#[test]
fn detects_bad_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	// Non-UUID filename.
	std::fs::write(inbox.join("not-a-uuid.eml"), b"Subject: x\r\n\r\nb").expect("write");
	// Valid UUID but no header/body separator.
	let bad = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{bad}.eml")), b"no separator here").expect("write");
	// Orphaned flags (no matching message).
	let orphan = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{orphan}.flags")), b"[\"\\\\Seen\"]").expect("write");

	let mut out = Vec::new();
	assert_eq!(
		run(dir.path(), &MessageCrypto::disabled(), false, &mut out),
		ExitCode::FAILURE
	);
	let report = String::from_utf8(out).expect("utf8");
	assert!(report.contains("not a UUID"), "{report}");
	assert!(report.contains("no header/body separator"), "{report}");
	assert!(report.contains("orphaned flags"), "{report}");
}

#[test]
fn missing_accounts_dir_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut out = Vec::new();
	assert_eq!(
		run(dir.path(), &MessageCrypto::disabled(), false, &mut out),
		ExitCode::SUCCESS
	);
}
