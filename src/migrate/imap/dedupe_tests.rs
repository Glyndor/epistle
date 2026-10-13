use super::*;

#[test]
fn message_id_is_found_unfolded_and_only_in_the_header() {
	assert_eq!(
		message_id(b"Subject: x\r\nMessage-Id:\r\n  <a@b>\r\n\r\nbody"),
		Some(b"<a@b>".to_vec())
	);
	assert_eq!(
		message_id(b"Subject: x\r\n\r\nMessage-ID: <late@b>\r\n"),
		None
	);
	assert_eq!(message_id(b"Message-ID:   \r\n\r\n"), None);
}

#[test]
fn keys_use_the_id_and_size_or_the_digest() {
	let a = key(b"Message-ID: <a@b>\r\n\r\none");
	let b = key(b"Message-ID: <a@b>\r\n\r\ntwo");
	assert_eq!(a, b, "same id and size");
	assert_ne!(
		a,
		key(b"Message-ID: <a@b>\r\n\r\nthree"),
		"same id, other size"
	);
	assert_ne!(key(b"Subject: x\r\n\r\none"), key(b"Subject: x\r\n\r\ntwo"));
}

#[test]
fn each_stored_copy_is_claimed_once() {
	let mut index = Index::default();
	let k = key(b"Message-ID: <a@b>\r\n\r\none");
	index.add(k.clone());
	assert!(index.claim(&k));
	assert!(
		!index.claim(&k),
		"a second identical message is stored again"
	);
}

#[test]
fn scan_reads_the_local_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::disabled();
	let body = b"Message-ID: <a@b>\r\n\r\none".to_vec();
	crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], &body, &crypto)
		.expect("append");
	let mut index = Index::scan(dir.path(), "alice", "INBOX", &crypto).expect("scan");
	assert!(index.claim(&key(&body)));
	let empty = Index::scan(dir.path(), "alice", "Nowhere", &crypto).expect("scan");
	assert!(empty.counts.is_empty());
}
