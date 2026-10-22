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
	let dir = tempfile::tempdir().unwrap();
	let mut index = Index {
		table: disk::Table::new(super::super::state::scratch(dir.path()).unwrap(), 1).unwrap(),
	};
	let k = key(b"Message-ID: <a@b>\r\n\r\none");
	index.table.add(&k).unwrap();
	assert!(index.claim(&k).unwrap());
	assert!(
		!index.claim(&k).unwrap(),
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
	let mut budget = Budget::default();
	let mut index = Index::scan(
		dir.path(),
		"alice",
		"INBOX",
		&crypto,
		&mut budget,
		1024,
		false,
	)
	.expect("scan");
	assert!(index.claim(&key(&body)).unwrap());
	let mut empty = Index::scan(
		dir.path(),
		"alice",
		"Nowhere",
		&crypto,
		&mut budget,
		1024,
		false,
	)
	.expect("scan");
	assert!(!empty.table.claim(&key(&body)).unwrap());
}

#[test]
fn recovery_scan_bounds_message_reads_and_decodes_encrypted_mail() {
	for crypto in [MessageCrypto::disabled(), MessageCrypto::for_test(&[9; 32])] {
		let dir = tempfile::tempdir().expect("dir");
		let body = b"12345678";
		crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], body, &crypto)
			.expect("append");
		let mut index = Index::scan(
			dir.path(),
			"alice",
			"INBOX",
			&crypto,
			&mut Budget::default(),
			body.len(),
			false,
		)
		.expect("fits exactly");
		assert!(index.claim(&key(body)).unwrap());
		assert!(
			matches!(
				Index::scan(
					dir.path(),
					"alice",
					"INBOX",
					&crypto,
					&mut Budget::default(),
					body.len() - 1,
					false,
				),
				Err(MigrateError::Storage(_))
			),
			"refuse a recovery body over the limit"
		);
	}
}

#[test]
fn recovery_scan_reserves_a_fixed_workspace_even_without_message_ids() {
	let dir = tempfile::tempdir().expect("dir");
	let crypto = MessageCrypto::disabled();
	for byte in b"abcdef" {
		crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], &[*byte], &crypto)
			.expect("append");
	}
	let mut budget = Budget::default();
	budget.mailbox_limit = 1024;
	assert!(matches!(
		Index::scan(
			dir.path(),
			"alice",
			"INBOX",
			&crypto,
			&mut budget,
			1024,
			false
		),
		Err(MigrateError::Client(super::super::ClientError::Metadata {
			scope: "mailbox",
			..
		}))
	));
}

#[test]
fn recovery_accepts_seventy_thousand_messages_with_bounded_metadata() {
	let dir = tempfile::tempdir().expect("dir");
	let crypto = MessageCrypto::disabled();
	let id = crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], b"a", &crypto)
		.expect("message");
	let mailbox = crate::imap::mailbox::mailbox_dir(dir.path(), "alice", "INBOX").unwrap();
	let first = mailbox.join(format!("{id}.eml"));
	for _ in 1..70_000 {
		std::fs::hard_link(
			&first,
			mailbox.join(format!("{}.eml", uuid::Uuid::now_v7())),
		)
		.expect("message entry");
	}
	for _ in 0..2 {
		let result = Index::scan(
			dir.path(),
			"alice",
			"INBOX",
			&crypto,
			&mut Budget::default(),
			1024,
			false,
		);
		assert!(
			result.is_ok(),
			"a large mailbox must remain recoverable: {result:?}"
		);
		let mut index = result.unwrap();
		for _ in 0..70_000 {
			assert!(
				index.claim(&key(b"a")).unwrap(),
				"retain every identical local copy"
			);
		}
		assert!(!index.claim(&key(b"a")).unwrap());
	}
}
