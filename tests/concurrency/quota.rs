//! Parallel DATA completions compete for the real mailbox's remaining bytes.

use super::{support::*, wire};
use epistle::smtp::quota::MailboxQuota;
use epistle::smtp::server::Server;
use epistle::storage::{LocalDelivery, MessageCrypto};
use std::sync::Arc;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_deliveries_preserve_quota_and_every_250() {
	seed("quota");
	const LINES: usize = 512;
	let root = tempfile::tempdir().expect("mail store");
	let directory = directory();
	// Allow four full copies, including ample trace-header overhead, but not five.
	let limit = (message(0, LINES, false).len() * 4 + 4096) as u64;
	let sink =
		Arc::new(LocalDelivery::new(root.path(), directory.clone()).expect("local delivery"));
	let quota = MailboxQuota::on_disk(root.path().to_path_buf(), MessageCrypto::disabled(), limit);
	let listener = Listener::start(
		Server::new("mx.epistle.test", sink)
			.with_directory(directory)
			.with_quota(Arc::new(quota)),
	)
	.await;
	// Initialise the mailbox through a real acknowledged delivery before racing
	// quota decisions, so folder creation is not a second variable.
	let mut control = listener.connect().await;
	data(&mut control, false).await;
	let mut baseline = message(TASKS, LINES, false);
	baseline.extend_from_slice(b".\r\n");
	wire::send(&mut control, &baseline).await;
	wire::expect(&mut control, wire::OK).await;
	wire::quit(&mut control).await;
	let barrier = Arc::new(Barrier::new(TASKS + 1));
	let mut tasks = tokio::task::JoinSet::new();
	for id in 0..TASKS {
		let mut stream = listener.connect().await;
		data(&mut stream, false).await;
		let barrier = barrier.clone();
		tasks.spawn(async move {
			// Queue the body before the barrier, so the race concentrates on finalisation.
			wire::send(&mut stream, &message(id, LINES, false)).await;
			barrier.wait().await;
			wire::send(&mut stream, b".\r\n").await;
			let reply = wire::line(&mut stream)
				.await
				.expect("DATA reply")
				.expect("open");
			assert!(
				reply == wire::OK || reply == "552 5.2.2 mailbox full\r\n",
				"seed={SEED:#x} id={id} unexpected rejection {reply:?}"
			);
			(id, reply == wire::OK)
		});
	}
	let accepted = tokio::time::timeout(DEADLINE, async {
		barrier.wait().await;
		let mut accepted = std::collections::BTreeMap::from([(TASKS, 1)]);
		while let Some(result) = tasks.join_next().await {
			let (id, ok) = result.expect("delivery task");
			if ok {
				accepted.insert(id, 1);
			}
		}
		accepted
	})
	.await
	.expect("quota race deadline");
	assert!(
		accepted.len() > 1,
		"seed={SEED:#x} no successful concurrent delivery"
	);
	let messages = mailbox(root.path());
	let bytes: u64 = messages.iter().map(|raw| raw.len() as u64).sum();
	let stored = inventory(messages, LINES, false);
	assert_eq!(
		stored, accepted,
		"seed={SEED:#x} every 250 stored exactly once"
	);
	assert!(
		bytes <= limit,
		"seed={SEED:#x} mailbox bytes={bytes} quota={limit} accepted={}",
		accepted.len()
	);
}
