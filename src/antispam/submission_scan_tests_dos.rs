//! One account cannot hold every inspection slot, the clamd queue is
//! bounded, and a message that always hits a cap is refused for good
//! rather than retried.

use std::time::{Duration, Instant};

use super::*;
use crate::antispam::attachments::corpus;
use crate::config::{AttachmentMode, Attachments};
use crate::smtp::sink::MemorySink;

fn policy(mode: AttachmentMode) -> Arc<Policy> {
	let section = Attachments {
		mode,
		..Attachments::default()
	};
	Arc::new(Policy::from_config(&section, 1 << 20).expect("mode is not off"))
}

fn message(data: Vec<u8>) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

fn sink_with_gate(gate: Arc<gate::Gate>, mode: AttachmentMode) -> (ScanningSink, Arc<MemorySink>) {
	let inner = Arc::new(MemorySink::new());
	let sink = ScanningSink {
		inner: inner.clone(),
		scanner: None,
		attachments: Some(policy(mode)),
		gate,
		metrics: None,
		webhook: None,
		workers: Default::default(),
	};
	(sink, inner)
}

fn submit(sink: &ScanningSink, account: &str, data: Vec<u8>) -> Result<(), SinkError> {
	sink.submit(
		message(data),
		uuid::Uuid::now_v7(),
		account,
		&std::collections::BTreeMap::new(),
	)
}

#[test]
fn the_gate_caps_each_account_and_the_whole_server() {
	let gate = gate::Gate::new(3, 2);
	let first = gate.try_enter("alice").expect("slot");
	let second = gate.try_enter("alice").expect("slot");
	assert!(gate.try_enter("alice").is_none(), "alice is at her share");
	let bob = gate.try_enter("bob").expect("bob still gets a slot");
	assert!(gate.try_enter("carol").is_none(), "the server is full");
	drop(first);
	assert!(
		gate.try_enter("carol").is_some(),
		"a freed slot is reusable"
	);
	drop((second, bob));
	assert_eq!(gate.senders(), 0, "no entry outlives its permits");
}

#[test]
fn an_account_at_its_share_is_asked_to_retry_while_others_go_through() {
	let (sink, inner) = sink_with_gate(gate::Gate::new(4, 1), AttachmentMode::Quarantine);
	let held = sink.gate.try_enter("alice").expect("slot");
	let error = submit(&sink, "alice", b"Subject: s\r\n\r\nhello\r\n".to_vec()).expect_err("busy");
	assert!(matches!(error, SinkError::ScanUnavailable), "{error}");
	assert_eq!(
		error.smtp_reply().to_string(),
		"451 4.7.1 content scan unavailable, try again later\r\n"
	);
	submit(&sink, "bob", b"Subject: s\r\n\r\nhello\r\n".to_vec()).expect("bob goes through");
	assert_eq!(inner.messages().len(), 1);
	drop(held);
	submit(&sink, "alice", b"Subject: s\r\n\r\nhello\r\n".to_vec())
		.expect("alice after her slot frees");
	assert_eq!(inner.messages().len(), 2);
}

#[test]
fn a_message_that_always_hits_a_cap_is_refused_permanently() {
	let mut bomb = String::from("Content-Type: multipart/mixed; boundary=z\r\n\r\n");
	for _ in 0..1200 {
		bomb.push_str("--z\r\nContent-Type: text/plain\r\n\r\nx\r\n");
	}
	let (sink, inner) = sink_with_gate(gate::Gate::new(4, 1), AttachmentMode::Quarantine);
	let error = submit(&sink, "alice", bomb.into_bytes()).expect_err("refused");
	assert!(
		matches!(&error, SinkError::AttachmentRefused(codes) if codes == "scan-limit"),
		"{error}"
	);
	assert_eq!(
		error.smtp_reply().code(),
		550,
		"permanent, so nothing retries it"
	);
	assert!(inner.messages().is_empty());
	assert_eq!(sink.gate.senders(), 0, "the slot was released");
	let _ = corpus::pe();
}

/// A clamd that accepts connections and never answers.
fn stalled_clamd(dir: &std::path::Path) -> std::path::PathBuf {
	let socket = dir.join("stalled.sock");
	let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
	std::thread::spawn(move || {
		let mut held = Vec::new();
		for stream in listener.incoming().flatten() {
			held.push(stream);
		}
	});
	socket
}

#[test]
fn a_full_clamd_queue_answers_busy_at_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd =
		Arc::new(ClamdHook::new(stalled_clamd(dir.path())).with_timeout(Duration::from_secs(3)));
	let scanner = Arc::new(worker::Scanner::start_with(clamd, 1, 1).expect("scanner"));
	let mut waiting = Vec::new();
	for _ in 0..2 {
		let scanner = Arc::clone(&scanner);
		waiting.push(std::thread::spawn(move || scanner.scan(b"x").is_some()));
		std::thread::sleep(Duration::from_millis(100));
	}
	let deadline = Instant::now() + Duration::from_secs(2);
	while scanner.queue_space() > 0 && Instant::now() < deadline {
		std::thread::sleep(Duration::from_millis(10));
	}
	let started = Instant::now();
	assert!(
		scanner.scan(b"x").is_none(),
		"a full queue must answer busy"
	);
	assert!(
		started.elapsed() < Duration::from_millis(500),
		"busy is answered at once, not after the scan deadline"
	);
	for thread in waiting {
		assert!(
			thread.join().expect("scan thread"),
			"admitted scans still finish"
		);
	}
}

#[test]
fn a_clamd_that_never_answers_gives_its_slot_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd = Arc::new(
		ClamdHook::new(stalled_clamd(dir.path())).with_timeout(Duration::from_millis(300)),
	);
	let scanner = worker::Scanner::start_with(clamd, 1, 1).expect("scanner");
	for round in 0..3 {
		let started = Instant::now();
		let (inspection, _) = scanner.scan(b"x").expect("admitted, not busy");
		assert_eq!(inspection, Inspection::Unscanned, "round {round}");
		assert!(
			started.elapsed() < Duration::from_secs(3),
			"round {round} waited past the deadline"
		);
	}
}

#[test]
fn one_account_flooding_heavy_messages_does_not_stall_another() {
	let (sink, inner) = sink_with_gate(gate::Gate::new(4, 1), AttachmentMode::Flag);
	let sink = Arc::new(sink);
	let heavy = corpus::message(&[corpus::attachment(
		"Content-Type: application/octet-stream; name=a.bin",
		&vec![b'A'; 2 << 20],
	)]);
	let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
	let busy = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let mut flooders = Vec::new();
	for _ in 0..6 {
		let (sink, heavy, stop, busy) = (
			Arc::clone(&sink),
			heavy.clone(),
			Arc::clone(&stop),
			Arc::clone(&busy),
		);
		flooders.push(std::thread::spawn(move || {
			while !stop.load(std::sync::atomic::Ordering::Relaxed) {
				if let Err(SinkError::ScanUnavailable) = submit(&sink, "mallory", heavy.clone()) {
					busy.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
				}
			}
		}));
	}
	std::thread::sleep(Duration::from_millis(200));
	let mut slowest = Duration::ZERO;
	for _ in 0..5 {
		let started = Instant::now();
		submit(&sink, "alice", b"Subject: s\r\n\r\nhello\r\n".to_vec()).expect("alice is admitted");
		slowest = slowest.max(started.elapsed());
	}
	stop.store(true, std::sync::atomic::Ordering::Relaxed);
	for flooder in flooders {
		flooder.join().expect("flooder");
	}
	assert!(
		slowest < Duration::from_secs(1),
		"alice waited {slowest:?} behind mallory"
	);
	assert!(
		busy.load(std::sync::atomic::Ordering::Relaxed) > 0,
		"mallory was held to her share"
	);
	assert!(inner.messages().len() >= 5);
}
