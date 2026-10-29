use super::*;

/// Write a raw message into an account's INBOX (`new`).
fn deliver(data_dir: &Path, account: &str, body: &[u8]) {
	let new_dir = data_dir.join("accounts").join(account).join("new");
	std::fs::create_dir_all(&new_dir).expect("dirs");
	let id = uuid::Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
}

#[test]
fn export_decrypts_encrypted_store_to_plaintext_mbox() {
	// With encryption on, the on-disk message is ciphertext but the exported
	// mbox stream must carry the plaintext.
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");
	mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: hi\r\n\r\nsecret export body\r\n",
		&crypto,
	)
	.expect("append");
	// The stored file is encrypted.
	let new_dir = dir.path().join("accounts").join("alice").join("new");
	let stored = std::fs::read_dir(&new_dir)
		.expect("new dir")
		.flatten()
		.map(|e| std::fs::read(e.path()).expect("read"))
		.next()
		.expect("one file");
	assert!(
		stored.starts_with(b"EPENC1\0"),
		"stored message is encrypted"
	);

	let mut out = Vec::new();
	assert_eq!(
		run(dir.path(), "alice", &crypto, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("secret export body"), "{text}");
}

#[test]
fn maildir_flags_are_canonical_order() {
	let flags = [Flag::Seen, Flag::Draft, Flag::Answered];
	// Output is always D F R S T order regardless of input order.
	assert_eq!(maildir_flags(&flags), "DRS");
	assert_eq!(maildir_flags(&[]), "");
	assert_eq!(maildir_flags(&[Flag::Deleted, Flag::Flagged]), "FT");
}

#[test]
fn maildir_export_writes_messages_to_cur() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"Subject: one\r\n\r\nbody one\r\n");
	deliver(dir.path(), "alice", b"Subject: two\r\n\r\nbody two\r\n");

	let out = tempfile::tempdir().expect("out");
	assert_eq!(
		run_maildir(dir.path(), "alice", &MessageCrypto::disabled(), out.path()),
		ExitCode::SUCCESS
	);
	let cur = out.path().join("cur");
	let files: Vec<_> = std::fs::read_dir(&cur)
		.expect("cur exists")
		.flatten()
		.collect();
	assert_eq!(files.len(), 2, "two messages exported");
	// Maildir filenames carry the `:2,` info suffix.
	assert!(
		files
			.iter()
			.all(|f| f.file_name().to_string_lossy().contains(":2,")),
		"maildir info suffix present"
	);
}

#[test]
fn maildir_export_round_trips_through_import() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"Subject: hello\r\n\r\nround trip\r\n");

	let out = tempfile::tempdir().expect("out");
	assert_eq!(
		run_maildir(dir.path(), "alice", &MessageCrypto::disabled(), out.path()),
		ExitCode::SUCCESS
	);

	// Import the exported Maildir into a fresh account and confirm the
	// message survives.
	let dest = tempfile::tempdir().expect("dest");
	assert_eq!(
		crate::cli::import::run_maildir(
			dest.path(),
			"bob",
			&MessageCrypto::disabled(),
			out.path(),
			false
		),
		ExitCode::SUCCESS
	);
	let snapshot =
		Snapshot::open(dest.path(), "bob", "INBOX", &MessageCrypto::disabled()).expect("inbox");
	assert_eq!(snapshot.messages().count(), 1);
	let message = snapshot.messages().next().expect("message");
	let data = snapshot.read(message).expect("read");
	assert!(
		String::from_utf8_lossy(&data).contains("round trip"),
		"content preserved"
	);
}
