//! A message that goes back and forth through real IMAP commands, the real
//! queue, the real worker and a real PostgreSQL leaves one record and the
//! corpus where the last move put it. Runs only when `DATABASE_URL` is set.

use super::*;
use crate::antispam::corpus::BayesStore;
use crate::antispam::learning::LearningStats;
use crate::antispam::training_queue::TrainingQueue;
use crate::metrics::Metrics;

async fn settle(store: &BayesStore, account: &str, lessons: i64) -> LearningStats {
	for _ in 0..200 {
		let stats = store.learning_stats(account).await.expect("stats");
		if stats.spam_learned + stats.ham_learned + stats.repeated >= lessons {
			return stats;
		}
		tokio::time::sleep(std::time::Duration::from_millis(25)).await;
	}
	store.learning_stats(account).await.expect("stats")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_moved_to_junk_and_back_leaves_one_record_and_the_last_verdict() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect");
	let mut key = [0u8; 32];
	key[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	key[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
	let store = BayesStore::with_key(pool, key);
	// The session's account is fixed, so clear what an earlier run left.
	store.forget_scope("alice").await.expect("clean start");
	let queue = TrainingQueue::start(
		Arc::new(store.clone()),
		crate::storage::MessageCrypto::disabled(),
		Arc::new(Metrics::new()),
	);
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"Subject: offer\r\n\r\nbuy cheap pills discount now friend\r\n",
	);
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory())
		.with_training(queue);
	let login = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	assert!(text(&login).contains("a1 OK"));
	session.command_line("a2 CREATE Junk");
	session.command_line("a3 SELECT INBOX");
	assert!(text(&session.command_line("a4 MOVE 1 Junk")).contains("a4 OK"));
	let mut lessons = 1;
	for round in 0..6 {
		session.command_line("b1 SELECT Junk");
		let out = session.command_line(&format!("c{round} MOVE 1 INBOX"));
		assert!(text(&out).contains("OK"), "round {round} out");
		lessons += 1;
		settle(&store, "alice", lessons).await;
		session.command_line("b2 SELECT INBOX");
		let back = session.command_line(&format!("d{round} MOVE 1 Junk"));
		assert!(text(&back).contains("OK"), "round {round} in");
		lessons += 1;
		settle(&store, "alice", lessons).await;
	}
	let stats = settle(&store, "alice", lessons).await;
	assert_eq!(stats.entries, 1, "one message, one record: {stats:?}");
	assert_eq!(
		(stats.corpus_spam, stats.corpus_ham),
		(1, 0),
		"the last move put it in Junk: {stats:?}"
	);
	store.forget_scope("alice").await.expect("cleanup");
}
