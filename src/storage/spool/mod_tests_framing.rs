//! What a queued message looks like on disk, whichever path queued it.

use super::*;

fn message(data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".into()],
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn queued(data: &[u8]) -> Vec<u8> {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let id = spool
		.store(&message(data), None, &BTreeMap::new())
		.expect("store");
	spool.load(id).expect("load").data
}

#[test]
fn a_lone_lf_is_queued_as_crlf() {
	assert_eq!(queued(b"Subject: s\n\nbody"), b"Subject: s\r\n\r\nbody\r\n");
}

#[test]
fn a_nul_or_a_bare_cr_is_refused_not_repaired() {
	for data in [
		b"Subject: s\r\n\r\nhello\r.\r\n".as_slice(),
		b"Subject: s\r\n\r\nbo\0dy\r\n".as_slice(),
		b"Bc\0c: x\r\n\r\nbody\r\n".as_slice(),
		b"a\r\0\nb".as_slice(),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		let error = spool
			.store(&message(data), None, &BTreeMap::new())
			.expect_err("refused");
		assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
		assert!(spool.list().expect("list").is_empty());
	}
}

#[test]
fn a_framed_message_is_queued_unchanged() {
	let data = b"Subject: s\r\n\r\nbody\r\n";
	assert_eq!(queued(data), data);
}

#[test]
fn the_evidence_record_sees_the_bytes_that_are_queued() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	let seen = std::sync::Mutex::new(Vec::new());
	let record = |data: &[u8]| {
		*seen.lock().expect("lock") = data.to_vec();
		Ok(())
	};
	let extra = BTreeMap::new();
	let id = spool
		.store_with(
			&message(b"Subject: s\r\n\r\na\nb\r\n"),
			Uuid::now_v7(),
			&StoreOptions {
				account: None,
				extra: &extra,
				class: crate::evidence::MailClass::Personal,
				evidence: Some(&record),
				retain_days: 0,
			},
		)
		.expect("store");
	let stored = spool.load(id).expect("load").data;
	assert_eq!(*seen.lock().expect("lock"), stored);
	assert_eq!(stored, b"Subject: s\r\n\r\na\r\nb\r\n");
}
