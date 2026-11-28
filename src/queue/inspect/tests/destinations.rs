//! The destinations read over part of the queue.

use std::collections::BTreeMap;

use super::super::destination_rows_within;
use crate::smtp::session::AcceptedMessage;
use crate::storage::{Budget, FsSpool};

#[test]
fn the_rows_say_when_entries_were_left_unread() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	for _ in 0..3 {
		spool
			.store(
				&AcceptedMessage {
					reverse_path: "alice@example.org".into(),
					recipients: vec!["bob@remote.example".into()],
					data: b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					sender_verified: false,
					no_dsn: Vec::new(),
				},
				None,
				&BTreeMap::new(),
			)
			.expect("store");
	}
	let partial = |budget| destination_rows_within(&spool, 0, budget).expect("rows").1;
	assert!(partial(Budget::new(2, usize::MAX)), "one entry unread");
	assert!(!partial(Budget::new(3, usize::MAX)), "all of them read");
	assert!(partial(Budget::new(3, 1)), "the bytes stop the walk");
}
