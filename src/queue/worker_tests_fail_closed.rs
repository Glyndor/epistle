//! The destination holds fail closed: holds that cannot be read stop the
//! queue from sending anything, and a hold that cannot be written still
//! applies, from memory, until it can be.

use super::tests_backoff::{greeting, store, worker_for};
use crate::queue::backoff;
use crate::queue::test_remote::FakeRemote;

const DOMAIN: &str = "busy.example";

#[tokio::test]
async fn unreadable_holds_send_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let (worker, _) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	std::fs::write(dir.path().join("spool/destinations.json"), b"{not json").expect("write");

	worker.pass().await.expect("pass");

	assert_eq!(remote.connections("mx.busy.example"), 0);
	let id = worker.spool.list().expect("list")[0];
	let state = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state("bob@busy.example");
	assert_eq!(state.attempts, 0, "nothing was attempted");
}

#[tokio::test]
async fn a_hold_that_cannot_be_written_still_applies() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	remote.script(DOMAIN, greeting("421 4.7.0 slow down"));
	let (worker, now) = worker_for(dir.path(), &["bob@busy.example"], &remote);
	store(&worker.spool, &["carol@busy.example"]);
	// No file can be written into the spool any more: its scratch
	// directory is now a file.
	let scratch = dir.path().join("spool/tmp");
	std::fs::remove_dir_all(&scratch).expect("remove tmp");
	std::fs::write(&scratch, b"").expect("block tmp");
	let worker = worker.with_concurrency(8, 1);

	let _ = worker.pass().await;

	assert_eq!(remote.connections("mx.busy.example"), 1);
	assert!(worker.spool.load_holds().expect("holds").is_empty());
	let holds = worker.holds().expect("holds in memory");
	assert!(backoff::is_held(&holds, DOMAIN, now));

	// The outcome could not be written either, so both messages are still
	// due, and the destination is not contacted again while it holds.
	let _ = worker.pass().await;
	assert_eq!(remote.connections("mx.busy.example"), 1);

	// Once the spool can be written again, the hold reaches the file.
	std::fs::remove_file(&scratch).expect("unblock tmp");
	std::fs::create_dir(&scratch).expect("tmp");
	let holds = worker.holds().expect("holds");
	assert!(backoff::is_held(&holds, DOMAIN, now));
	assert!(
		worker
			.spool
			.load_holds()
			.expect("holds")
			.contains_key(DOMAIN)
	);
}

#[tokio::test]
async fn a_held_sender_waits_and_the_others_do_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let spool = crate::storage::FsSpool::open(dir.path()).expect("open spool");
	for (recipient, account) in [("x@a.example", "flood"), ("y@b.example", "bob")] {
		spool
			.store(
				&crate::smtp::session::AcceptedMessage {
					reverse_path: format!("{account}@sender.example"),
					recipients: vec![recipient.into()],
					data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					sender_verified: false,
					no_dsn: Vec::new(),
				},
				Some(account),
				&std::collections::BTreeMap::new(),
			)
			.expect("store");
	}
	let now = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	spool
		.update_holds(|holds| {
			backoff::record_hold(
				holds,
				&[3600],
				(&"a".repeat(backoff::MAX_KEY_BYTES + 1), "account:flood"),
				"421 slow down",
				now,
			);
		})
		.expect("hold");
	let worker = super::Worker::new(
		spool,
		std::sync::Arc::new(remote.clone()),
		"mail.sender.example",
	);
	worker.set_now(now + 1);

	worker.pass().await.expect("pass");

	assert_eq!(remote.copies("x@a.example"), 0, "the held sender waits");
	assert_eq!(remote.copies("y@b.example"), 1);
}

#[tokio::test]
async fn one_account_flooding_the_holds_does_not_stop_another_accounts_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let remote = FakeRemote::default();
	let spool = crate::storage::FsSpool::open(dir.path()).expect("open spool");
	spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "bob@sender.example".into(),
				recipients: vec!["carol@fresh.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			Some("bob"),
			&std::collections::BTreeMap::new(),
		)
		.expect("store");
	let now = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	// The flood: far more deferring destinations than any share, all of
	// them in force for a day.
	spool
		.update_holds(|holds| {
			for n in 0..(backoff::MAX_HOLDS * 2) {
				let key = format!("junk{n}.example");
				backoff::record_hold(holds, &[86_400], (&key, "account:flood"), "421", now);
			}
		})
		.expect("holds");
	let holds = spool.load_holds().expect("holds");
	assert!(
		holds.len() <= backoff::MAX_HOLDS_PER_SENDER + 1,
		"{}",
		holds.len()
	);
	assert!(backoff::is_held(&holds, "sender:account:flood", now));
	let worker = super::Worker::new(
		spool,
		std::sync::Arc::new(remote.clone()),
		"mail.sender.example",
	);
	worker.set_now(now + 1);

	worker.pass().await.expect("pass");

	assert_eq!(remote.copies("carol@fresh.example"), 1);
	// No mail waits for the junk any more once its holds run out: they go.
	worker.set_now(now + 86_401);
	worker.pass().await.expect("pass");
	let holds = worker.spool.load_holds().expect("holds");
	assert!(holds.is_empty(), "{} holds left", holds.len());
}
