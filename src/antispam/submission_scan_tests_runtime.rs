//! Submissions are inspected inside a synchronous sink, called from
//! whatever runs the caller: the server's multi-threaded runtime (SMTP
//! after AUTH, the API, JMAP), a current-thread runtime in tests, or a
//! plain thread. None of them may crash on the inspection, and a panic in
//! it is a temporary failure, never a dead session.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::antispam::attachments::corpus;
use crate::config::{AttachmentMode, Attachments};
use crate::smtp::sink::MemorySink;

/// A hook that counts the inspections it sees, and the count: one per test,
/// so another test's inspections never move it.
fn counting() -> (impl Fn() + Send + Sync + 'static, Arc<AtomicUsize>) {
	let inspected = Arc::new(AtomicUsize::new(0));
	let seen = Arc::clone(&inspected);
	let hook = move || {
		seen.fetch_add(1, Ordering::SeqCst);
	};
	(hook, inspected)
}

fn explode() {
	panic!("inspection failed on purpose");
}

fn policy(mode: AttachmentMode) -> Policy {
	let section = Attachments {
		mode,
		..Attachments::default()
	};
	Policy::from_config(&section, 1 << 20).expect("mode is not off")
}

fn disguised() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data: corpus::message(&[corpus::attachment(
			"Content-Type: application/pdf; name=\"factura.pdf.exe\"",
			&corpus::pe(),
		)]),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

fn make(policy: Policy) -> (Arc<dyn MessageSink>, Arc<MemorySink>) {
	let inner = Arc::new(MemorySink::new());
	let sink = ScanningSink::wrap_with_attachments(
		true,
		inner.clone(),
		None,
		Some(Arc::new(policy)),
		None,
		None,
	)
	.expect("sink");
	(sink, inner)
}

fn submit(sink: &Arc<dyn MessageSink>) -> Result<(), SinkError> {
	sink.submit(
		disguised(),
		uuid::Uuid::now_v7(),
		"alice",
		&crate::smtp::sink::Submission::default(),
	)
}

fn refused(result: Result<(), SinkError>) -> bool {
	matches!(result, Err(SinkError::AttachmentRefused(_)))
}

#[test]
fn a_panicking_inspection_is_a_temporary_failure() {
	let (sink, inner) = make(policy(AttachmentMode::Quarantine).with_check_hook(explode));
	let error = submit(&sink).expect_err("not sent");
	assert_eq!(
		error.smtp_reply().to_string(),
		"451 4.7.1 content scan unavailable, try again later\r\n"
	);
	assert!(inner.messages().is_empty(), "nothing was routed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_inspection_on_the_server_runtime_is_a_temporary_failure() {
	let (sink, inner) = make(policy(AttachmentMode::Reject).with_check_hook(explode));
	assert!(matches!(submit(&sink), Err(SinkError::ScanUnavailable)));
	assert!(inner.messages().is_empty());
}

#[test]
fn every_caller_the_sink_can_have_gets_the_verdict() {
	let (sink, _) = make(policy(AttachmentMode::Quarantine));
	assert!(refused(submit(&sink)), "a plain thread");
	let current = tokio::runtime::Builder::new_current_thread()
		.build()
		.expect("runtime");
	assert!(
		refused(current.block_on(async { submit(&sink) })),
		"a current-thread runtime"
	);
	let multi = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.build()
		.expect("runtime");
	let on_worker = Arc::clone(&sink);
	assert!(
		refused(
			multi
				.block_on(multi.spawn(async move { submit(&on_worker) }))
				.expect("task")
		),
		"a worker of the multi-threaded runtime"
	);
	let on_pool = Arc::clone(&sink);
	assert!(
		refused(
			multi
				.block_on(multi.spawn_blocking(move || submit(&on_pool)))
				.expect("task")
		),
		"the blocking pool"
	);
	assert!(
		refused(multi.block_on(async { submit(&sink) })),
		"the runtime's own block_on"
	);
}

#[test]
fn flag_mode_never_inspects_a_submission() {
	// Under `flag` no finding can stop a submission, and nothing is
	// stamped on outgoing mail: an inspection would only cost time and,
	// at the gate's cap, a 451 an upgrade never asked for.
	let (count, inspected) = counting();
	let (sink, inner) = make(policy(AttachmentMode::Flag).with_check_hook(count));
	submit(&sink).expect("sent");
	assert_eq!(inner.messages().len(), 1);
	assert_eq!(inspected.load(Ordering::SeqCst), 0, "not inspected");
	let (count, inspected) = counting();
	let (sink, _) = make(policy(AttachmentMode::Quarantine).with_check_hook(count));
	assert!(refused(submit(&sink)));
	assert_eq!(inspected.load(Ordering::SeqCst), 1);
}
