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
	let mut source = mailbox.join(format!("{id}.eml"));
	for entry in 1..70_000 {
		// A file system caps the links to one file (about 65000 on ext4), so a
		// new source is made every 30000 entries instead of linking one file
		// 70000 times, which fails on the file system of some runners.
		if entry % 30_000 == 0 {
			let next = mailbox.join(format!("{}.eml", uuid::Uuid::now_v7()));
			std::fs::copy(&source, &next).expect("new source");
			source = next;
			// The copy is itself one of the 70000 entries.
			continue;
		}
		std::fs::hard_link(
			&source,
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

#[test]
fn a_recovery_scan_synchronizes_the_directories_once_not_once_per_message() {
	use crate::migrate::imap::durability::tests;
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::disabled();
	for n in 0..40 {
		let body = format!("Message-ID: <{n}@b>\r\n\r\none");
		crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], body.as_bytes(), &crypto)
			.expect("append");
	}
	let _guard = tests::begin(None);
	Index::scan(
		dir.path(),
		"alice",
		"INBOX",
		&crypto,
		&mut Budget::default(),
		1024,
		true,
	)
	.expect("scan");
	let events = tests::events();
	let count = |kind| events.iter().filter(|event| **event == kind).count();
	assert_eq!(count("message"), 40, "every message body is synchronized");
	assert_eq!(count("mailbox-directory"), 1, "{events:?}");
	assert!(count("mailbox-parent") >= 1, "{events:?}");
	assert!(
		events.len() < 40 * 3 + 10,
		"{} barriers for 40 messages",
		events.len()
	);
}

#[test]
fn a_scan_stops_at_the_total_deadline_instead_of_finishing_the_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::disabled();
	crate::imap::mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: x\r\n\r\none",
		&crypto,
	)
	.expect("append");
	let mut budget = Budget::default();
	budget.deadline = Some(std::time::Instant::now());
	let result = Index::scan(
		dir.path(),
		"alice",
		"INBOX",
		&crypto,
		&mut budget,
		1024,
		false,
	);
	assert!(matches!(result, Err(MigrateError::Timeout)), "{result:?}");
	let mut budget = Budget::default();
	budget.deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(3600));
	Index::scan(
		dir.path(),
		"alice",
		"INBOX",
		&crypto,
		&mut budget,
		1024,
		false,
	)
	.expect("a deadline in the future lets the scan finish");
}
