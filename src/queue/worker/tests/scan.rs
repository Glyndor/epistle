//! A scan of the spool goes on past an entry it cannot handle: one broken
//! entry must never keep every entry after it from being delivered. And
//! the give-up window holds for mail that waits for a slot: a message is
//! bounced when it is too old, not when its turn finally comes.

use std::time::Duration;

use super::*;
use crate::queue::test_remote::{FakeRemote, Hang, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MemorySink;

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

#[tokio::test(start_paused = true)]
async fn mail_waiting_for_a_slow_destination_still_expires_on_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	for user in ["a", "b", "c"] {
		store(&spool, &format!("{user}@slow.example"));
	}
	let created = spool.list().expect("list")[2]
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	let remote = FakeRemote::default();
	remote.script("slow.example", Script::hang(Hang::Greeting));
	let bounces = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_concurrency(1, 1)
		.with_max_age(3600)
		.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>);
	worker.set_now(created + 1);
	let worker = Arc::new(worker);
	let running = tokio::spawn(Arc::clone(&worker).run(Duration::from_secs(30)));
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert_eq!(remote.connections("mx.slow.example"), 1);

	// The give-up window closes while the first conversation still waits
	// for its greeting and the two other messages wait for the slot.
	worker.set_now(created + 3600);
	tokio::time::sleep(Duration::from_secs(31)).await;

	let left = worker.spool.list().expect("list");
	let bounced = bounces.messages().len();
	running.abort();
	assert_eq!(bounced, 2, "the two waiting messages are bounced at once");
	assert_eq!(left.len(), 1, "only the one in conversation is left");
	assert_eq!(remote.connections("mx.slow.example"), 1);
}
