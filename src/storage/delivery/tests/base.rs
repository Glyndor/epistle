use super::*;

pub(in super::super) fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("also-alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	))
}

pub(in super::super) fn message(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn list_inbox(root: &std::path::Path, account: &str) -> Vec<PathBuf> {
	let dir = root.join("accounts").join(account).join("new");
	match fs::read_dir(dir) {
		Ok(entries) => entries.map(|e| e.expect("entry").path()).collect(),
		Err(_) => Vec::new(),
	}
}

#[test]
fn delivers_one_copy_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");

	delivery
		.deliver(message(&[
			"alice@example.org",
			"also-alice@example.org",
			"bob@example.org",
		]))
		.expect("delivery succeeds");

	// Two addresses for alice still mean one copy.
	assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
	assert_eq!(list_inbox(dir.path(), "bob").len(), 1);
}

#[test]
fn delivered_file_contains_message_data() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("delivery succeeds");

	let files = list_inbox(dir.path(), "alice");
	let content = fs::read(&files[0]).expect("read delivered file");
	assert_eq!(
		content,
		b"Return-Path: <sender@elsewhere.example>\r\nDelivered-To: alice@example.org\r\n\
			  Subject: hi\r\n\r\nbody\r\n"
	);
}

fn folder_count(root: &std::path::Path, account: &str, mailbox: &str) -> usize {
	fs::read_dir(
		root.join("accounts")
			.join(account)
			.join("folders")
			.join(mailbox)
			.join("new"),
	)
	.map(|entries| {
		entries
			.flatten()
			.filter(|entry| entry.file_name().to_string_lossy().ends_with(".eml"))
			.count()
	})
	.unwrap_or(0)
}

fn write_filter(root: &std::path::Path, account: &str, script: &str) {
	let dir = root.join("accounts").join(account);
	fs::create_dir_all(&dir).expect("mkdir");
	fs::write(dir.join("filter.sieve"), script).expect("write filter");
}

#[test]
fn sieve_filter_files_into_chosen_folder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	write_filter(
		dir.path(),
		"alice",
		"if header :contains \"Subject\" \"hi\" { fileinto \"Filed\"; }",
	);
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	assert_eq!(folder_count(dir.path(), "alice", "Filed"), 1);
	assert!(list_inbox(dir.path(), "alice").is_empty());
}

#[test]
fn sieve_imap4flags_writes_flag_sidecar() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	write_filter(dir.path(), "alice", "addflag \"\\\\Seen\"; keep;");
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// The delivered message carries a .flags sidecar with \Seen.
	let new_dir = dir.path().join("accounts").join("alice").join("new");
	let sidecar = fs::read_dir(&new_dir)
		.expect("new dir")
		.map(|e| e.expect("entry").path())
		.find(|p| p.extension().is_some_and(|ext| ext == "flags"))
		.expect("flags sidecar written");
	let body = fs::read_to_string(sidecar).expect("read sidecar");
	// The sidecar keeps the legacy wire shape: a bare lowercase token
	// for system flags, so old readers see no format drift.
	assert!(body.contains("\"seen\""), "{body}");
}

#[test]
fn sieve_discard_drops_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	write_filter(dir.path(), "alice", "discard;");
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	assert!(list_inbox(dir.path(), "alice").is_empty());
	assert_eq!(folder_count(dir.path(), "alice", "Filed"), 0);
}

#[test]
fn invalid_filter_falls_back_to_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	// A syntactically broken script must not drop mail.
	write_filter(dir.path(), "alice", "if header { oops");
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
}

#[test]
fn quarantine_hint_overrides_sieve() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("delivery");
	write_filter(dir.path(), "alice", "fileinto \"Filed\";");
	let mut msg = message(&["alice@example.org"]);
	msg.recipients = vec!["alice@example.org".to_string()];
	// An explicit hint (e.g. spam quarantine) wins over the user filter.
	delivery
		.deliver_routed(&msg, Some("Rejects"))
		.expect("deliver");
	assert_eq!(folder_count(dir.path(), "alice", "Rejects"), 1);
	assert_eq!(folder_count(dir.path(), "alice", "Filed"), 0);
}

#[test]
fn unresolvable_recipient_fails_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
	let result = delivery.deliver(message(&["stranger@example.org"]));
	assert!(result.is_err());
	assert!(list_inbox(dir.path(), "alice").is_empty());
}

#[test]
fn empty_recipient_list_fails_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
	assert!(delivery.deliver(message(&[])).is_err());
}

#[test]
fn tmp_leftovers_are_not_visible_in_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
	delivery
		.deliver(message(&["alice@example.org"]))
		.expect("delivery succeeds");
	// Simulate a crashed write.
	fs::write(dir.path().join("accounts/alice/tmp/crash.eml"), b"partial").expect("write tmp");
	assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
}
