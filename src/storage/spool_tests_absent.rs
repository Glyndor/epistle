//! Work done only while the queue holds nothing under an id.

use std::collections::BTreeMap;

use super::FsSpool;
use crate::smtp::session::AcceptedMessage;

fn message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "a@example.org".into(),
		recipients: vec!["b@example.net".into()],
		data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

#[test]
fn the_work_runs_only_when_nothing_is_there() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = uuid::Uuid::now_v7();
	assert_eq!(spool.while_absent(id, || Ok(7)).expect("absent"), 7);
	let queued = spool
		.store(&message(), None, &BTreeMap::new())
		.expect("store");
	let refused = spool
		.while_absent(queued, || Ok(()))
		.expect_err("the queue holds it");
	assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn an_entry_that_cannot_be_looked_at_is_not_an_entry_that_is_absent() {
	use std::os::unix::fs::symlink;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = uuid::Uuid::now_v7();
	// A link out of the spool in the place of the envelope: it is not followed
	// and not taken for nothing.
	let outside = dir.path().join("elsewhere");
	std::fs::write(&outside, b"x").expect("target");
	symlink(&outside, dir.path().join(format!("spool/new/{id}.json"))).expect("link");
	let mut ran = false;
	let result = spool.while_absent(id, || {
		ran = true;
		Ok(())
	});
	assert!(result.is_err());
	assert!(!ran, "the work ran with something under the id");
}
