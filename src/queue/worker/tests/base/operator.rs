//! The worker honours edits the operator CLI makes to spooled entries.

use super::*;

fn loopback(sink: &Arc<MemorySink>) -> Arc<LoopbackConnector> {
	Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	})
}

fn only_id(spool: &FsSpool) -> uuid::Uuid {
	spool.list().expect("list")[0]
}

#[tokio::test]
async fn a_held_entry_is_never_attempted_until_released() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let id = only_id(&spool);
	let sink = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, loopback(&sink), "mail.sender.example");

	worker
		.spool
		.update_envelope(id, |e| e.hold(1))
		.expect("hold");
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(worker.spool.list().expect("list").len(), 1);
	assert!(sink.messages().is_empty(), "a held entry must not be sent");
	assert_eq!(worker.spool.load_envelope(id).expect("load").attempts, 0);

	worker
		.spool
		.update_envelope(id, |e| e.release(2))
		.expect("release");
	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert!(worker.spool.list().expect("list").is_empty());
	assert_eq!(sink.messages().len(), 1);
}

#[tokio::test]
async fn retry_now_overrides_the_backoff_without_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let id = only_id(&spool);
	let created = created_at(&spool);
	let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example");
	worker.set_now(created + 10);

	assert_eq!(worker.pass().await.expect("pass"), 0);
	let first = worker.spool.load_envelope(id).expect("load");
	assert_eq!(first.attempts, 1);
	assert!(first.next_attempt > created + 10, "backoff must be set");

	// Still backing off at the same instant: no second attempt.
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(worker.spool.load_envelope(id).expect("load").attempts, 1);

	// The operator asks for a retry now; the same worker attempts again.
	worker
		.spool
		.update_envelope(id, |e| e.next_attempt = 0)
		.expect("retry");
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(worker.spool.load_envelope(id).expect("load").attempts, 2);
}

#[tokio::test]
async fn a_failed_attempt_records_the_reason_for_queue_show() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let id = only_id(&spool);
	let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example");
	worker.set_now(created_at(&worker.spool) + 10);
	worker.pass().await.expect("pass");
	assert_eq!(
		worker
			.spool
			.load_envelope(id)
			.expect("load")
			.last_error
			.as_deref(),
		Some("connection refused")
	);
}

#[tokio::test]
async fn time_spent_on_hold_does_not_count_toward_giving_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let id = only_id(&spool);
	let created = created_at(&spool);
	let bounce_sink = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>)
		.with_max_age(3600);

	// Held for two hours, longer than the one-hour give-up window.
	worker
		.spool
		.update_envelope(id, |e| {
			e.hold(created + 10);
			e.release(created + 10 + 7200);
		})
		.expect("hold and release");
	worker.set_now(created + 7200 + 20);
	assert_eq!(worker.pass().await.expect("pass"), 0);

	assert_eq!(
		worker.spool.list().expect("list").len(),
		1,
		"a message parked by the operator must survive its first attempt"
	);
	assert!(bounce_sink.messages().is_empty());
}
