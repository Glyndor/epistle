use super::*;

fn sample_message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".into()],
		data: b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

#[test]
fn stores_and_loads_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");

	let id = spool
		.store(&sample_message(), None, &BTreeMap::new())
		.expect("store");
	let entry = spool.load(id).expect("load");

	assert_eq!(entry.envelope.id, id);
	assert_eq!(entry.envelope.reverse_path, "alice@example.org");
	assert_eq!(
		entry.envelope.recipients,
		vec!["bob@example.org".to_string()]
	);
	assert_eq!(entry.data, sample_message().data);
}

#[test]
fn store_preserves_require_tls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let mut message = sample_message();
	message.require_tls = true;
	let id = spool
		.store(&message, None, &BTreeMap::new())
		.expect("store");
	assert!(spool.load(id).expect("load").envelope.require_tls);
}

#[test]
fn list_returns_ids_oldest_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");

	let first = spool
		.store(&sample_message(), None, &BTreeMap::new())
		.expect("store first");
	let second = spool
		.store(&sample_message(), None, &BTreeMap::new())
		.expect("store second");

	assert_eq!(spool.list().expect("list"), vec![first, second]);
}

#[test]
fn remove_deletes_both_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");

	let id = spool
		.store(&sample_message(), None, &BTreeMap::new())
		.expect("store");
	spool.remove(id).expect("remove");

	assert!(spool.list().expect("list").is_empty());
	assert!(spool.load(id).is_err());
}

#[test]
fn load_unknown_id_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	assert!(spool.load(Uuid::now_v7()).is_err());
}

#[test]
fn list_ignores_foreign_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	fs::write(dir.path().join("spool/new/readme.txt"), b"not mail").expect("write");
	fs::write(dir.path().join("spool/new/bad.json"), b"{}").expect("write");
	assert!(spool.list().expect("list").is_empty());
}

#[test]
fn incomplete_tmp_files_are_invisible() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	// Simulate a crash: files in tmp/ never renamed.
	fs::write(dir.path().join("spool/tmp/crash.eml"), b"partial").expect("write");
	assert!(spool.list().expect("list").is_empty());
}

#[test]
fn sink_implementation_stores_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	spool.deliver(sample_message()).expect("deliver");
	assert_eq!(spool.list().expect("list").len(), 1);
}

#[test]
fn open_fails_on_unwritable_root() {
	let result = FsSpool::open(Path::new("/proc/no-such-dir"));
	assert!(result.is_err());
}
