//! A scan of the spool goes on past an entry it cannot handle: one broken
//! entry must never keep every entry after it from being delivered.

use super::*;
use crate::queue::test_remote::FakeRemote;
use crate::smtp::session::AcceptedMessage;

fn store(spool: &FsSpool, recipient: &str) -> uuid::Uuid {
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec![recipient.to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
				sender_verified: false,
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("store")
}

/// Every file under `dir` whose name holds `id` and ends in `.eml`.
fn message_files(dir: &std::path::Path, id: uuid::Uuid) -> Vec<std::path::PathBuf> {
	let mut found = Vec::new();
	let mut pending = vec![dir.to_path_buf()];
	while let Some(next) = pending.pop() {
		for item in std::fs::read_dir(&next).expect("read_dir") {
			let path = item.expect("entry").path();
			if path.is_dir() {
				pending.push(path);
			} else if path.to_string_lossy().contains(&id.to_string())
				&& path.extension().is_some_and(|ext| ext == "eml")
			{
				found.push(path);
			}
		}
	}
	found
}

#[tokio::test]
async fn an_entry_that_cannot_be_settled_does_not_stop_the_entries_after_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	// The older entry has a recipient no server could be asked about, and
	// its message is gone, so it cannot be recorded as refused.
	let broken = store(&spool, "not an address");
	let files = message_files(dir.path(), broken);
	assert_eq!(files.len(), 1, "{files:?}");
	std::fs::remove_file(&files[0]).expect("remove message");
	store(&spool, "bob@healthy.example");
	let remote = FakeRemote::default();
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example");

	let outcome = worker.pass().await;

	assert_eq!(remote.copies("bob@healthy.example"), 1);
	assert!(outcome.is_err(), "the broken entry is still reported");
}
