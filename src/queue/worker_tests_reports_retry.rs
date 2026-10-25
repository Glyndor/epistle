//! A failure report the sink refuses is tried again after a growing wait,
//! at most [`MAX_REPORT_ATTEMPTS`] times, and a recipient that is gone is not
//! tried again at all.

use super::report_failures::{MAX_REPORT_ATTEMPTS, report_wait};
use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink, SinkError};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A sink that refuses with `error` until told to take messages, counting
/// the calls.
struct Flaky {
	open: AtomicBool,
	gone: bool,
	calls: AtomicUsize,
	inner: MemorySink,
}

impl Flaky {
	fn new(gone: bool) -> Arc<Self> {
		Arc::new(Flaky {
			open: AtomicBool::new(false),
			gone,
			calls: AtomicUsize::new(0),
			inner: MemorySink::new(),
		})
	}
}

impl MessageSink for Flaky {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.calls.fetch_add(1, Ordering::SeqCst);
		match (self.open.load(Ordering::SeqCst), self.gone) {
			(true, _) => self.inner.deliver(message),
			(false, true) => Err(SinkError::Gone("recipient ghost no longer resolves".into())),
			(false, false) => Err(SinkError::Unavailable("refused for the test".into())),
		}
	}
}

fn worker_with(sink: &Arc<Flaky>) -> (tempfile::TempDir, Worker, u64) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["carol@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
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
	let start = spool.list().expect("list")[0]
		.get_timestamp()
		.expect("v7 timestamp")
		.to_unix()
		.0;
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.1.1 no such user"),
	);
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(sink.clone() as Arc<dyn MessageSink>)
		.with_max_age(5 * 3600);
	(dir, worker, start)
}

/// The state of the recipient, or `None` once the entry is gone.
fn state(worker: &Worker) -> Option<crate::storage::RecipientState> {
	let id = *worker.spool.list().expect("list").first()?;
	Some(
		worker
			.spool
			.load_envelope(id)
			.expect("envelope")
			.recipient_state("carol@remote.example"),
	)
}

#[tokio::test]
async fn a_refused_failure_report_waits_and_goes_out_later() {
	let sink = Flaky::new(false);
	let (_dir, worker, start) = worker_with(&sink);

	worker.set_now(start + 1);
	let _ = worker.pass().await;
	assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
	assert!(
		!state(&worker).expect("entry kept").reported,
		"a refused report is not reported"
	);

	// Inside the wait nothing is tried.
	worker.set_now(start + 60);
	let _ = worker.pass().await;
	assert_eq!(sink.calls.load(Ordering::SeqCst), 1);

	sink.open.store(true, Ordering::SeqCst);
	worker.set_now(start + 1000);
	let _ = worker.pass().await;
	assert_eq!(sink.inner.messages().len(), 1, "the report goes out later");
	assert!(state(&worker).is_none(), "reported, so the entry is done");
}

#[tokio::test]
async fn a_report_the_sink_always_refuses_is_given_up_on_after_the_cap() {
	let sink = Flaky::new(false);
	let (_dir, worker, start) = worker_with(&sink);

	for step in 1..=12u64 {
		worker.set_now(start + step * 30_000);
		let _ = worker.pass().await;
	}
	assert_eq!(
		sink.calls.load(Ordering::SeqCst),
		MAX_REPORT_ATTEMPTS as usize,
		"tried the capped number of times and no more"
	);
	assert!(
		state(&worker).is_none(),
		"given up on, so never tried again and the entry is done"
	);
	assert!(sink.inner.messages().is_empty());
}

#[tokio::test]
async fn a_report_for_a_recipient_that_is_gone_is_dropped_at_once() {
	let sink = Flaky::new(true);
	let (_dir, worker, start) = worker_with(&sink);

	for step in 1..=4u64 {
		worker.set_now(start + step * 30_000);
		let _ = worker.pass().await;
	}
	assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
	assert!(state(&worker).is_none(), "dropped, so the entry is done");
}

#[test]
fn the_wait_grows_each_time() {
	let waits: Vec<u64> = (1..MAX_REPORT_ATTEMPTS).map(report_wait).collect();
	assert_eq!(waits, vec![300, 1200, 4800, 19_200]);
}
