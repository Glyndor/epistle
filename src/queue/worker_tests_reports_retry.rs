//! A failure report the sink refuses is sent again on a later pass: the
//! recipients are marked reported only once it has been queued.

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink, SinkError};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// A sink that refuses until told to take messages.
struct Flaky {
	open: AtomicBool,
	inner: MemorySink,
}

impl MessageSink for Flaky {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		match self.open.load(Ordering::SeqCst) {
			true => self.inner.deliver(message),
			false => Err(SinkError::Unavailable("refused for the test".into())),
		}
	}
}

#[tokio::test]
async fn a_refused_failure_report_is_not_marked_reported_and_goes_out_later() {
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
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.1.1 no such user"),
	);
	let sink = Arc::new(Flaky {
		open: AtomicBool::new(false),
		inner: MemorySink::new(),
	});
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(sink.clone() as Arc<dyn MessageSink>)
		.with_max_age(5 * 3600);

	let _ = worker.pass().await;
	assert!(sink.inner.messages().is_empty());
	let id = worker.spool.list().expect("list")[0];
	let state = worker
		.spool
		.load_envelope(id)
		.expect("envelope")
		.recipient_state("carol@remote.example");
	assert!(!state.reported, "a refused report is not a reported one");

	sink.open.store(true, Ordering::SeqCst);
	let _ = worker.pass().await;
	assert_eq!(sink.inner.messages().len(), 1, "the report goes out later");
}
