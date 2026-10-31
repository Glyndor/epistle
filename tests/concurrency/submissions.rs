//! A deleted account limit must allow 64 messages and trip the exact-N assertion.

use super::{support::*, wire};
use epistle::smtp::ratelimit::SendLimiter;
use std::sync::Arc;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_submissions_accept_exactly_the_account_limit() {
	seed("submissions");
	const LIMIT: usize = 7;
	let tls = Tls::new();
	let password = &*wire::PASSWORD;
	let hash = epistle::smtp::auth::hash_password(password).expect("password hash");
	let sink = Arc::new(epistle::smtp::sink::MemorySink::new());
	let server = epistle::smtp::server::Server::new("mx.epistle.test", sink.clone())
		.with_directory(epistle::directory_store::DirectoryHandle::new(
			wire::directory().with_password_hashes([("tester".into(), hash)]),
		))
		// One long fixed window keeps wall-clock rollovers out of this concurrency test.
		.with_send_limiter(Arc::new(SendLimiter::for_authenticated_keys(86_400)))
		.with_global_submission_rate_limit(Some(LIMIT as u32));
	let listener = Listener::start(tls.server(server)).await;
	let barrier = Arc::new(Barrier::new(TASKS + 1));
	let mut tasks = tokio::task::JoinSet::new();
	for id in 0..TASKS {
		let mut stream = tls.connect(&listener).await;
		login(&mut stream, password).await;
		data(&mut stream, true).await;
		let barrier = barrier.clone();
		tasks.spawn(async move {
			barrier.wait().await;
			let mut raw = message(id, 4, true);
			raw.extend_from_slice(b".\r\n");
			wire::send(&mut stream, &raw).await;
			let reply = wire::line(&mut stream)
				.await
				.expect("DATA reply")
				.expect("open");
			assert!(
				reply == wire::OK
					|| reply == "450 4.7.1 sending rate limit exceeded; retry later\r\n",
				"seed={SEED:#x} id={id} {reply:?}"
			);
			(id, reply == wire::OK)
		});
	}
	let accepted = tokio::time::timeout(DEADLINE, async {
		barrier.wait().await;
		let mut accepted = std::collections::BTreeMap::new();
		while let Some(result) = tasks.join_next().await {
			let (id, ok) = result.expect("submission task");
			if ok {
				accepted.insert(id, 1);
			}
		}
		accepted
	})
	.await
	.expect("submission deadline");
	assert_eq!(accepted.len(), LIMIT, "seed={SEED:#x} exact account cap");
	let stored = inventory(
		sink.messages().into_iter().map(|m| m.data).collect(),
		4,
		true,
	);
	assert_eq!(stored, accepted, "seed={SEED:#x} acknowledged submissions");
}
