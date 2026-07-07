//! Macro (end-to-end) profiling workload for the receive -> store -> read pipeline.
//!
//! The criterion micro-benches in `benches/` time individual functions; they do
//! not show where wall-clock time goes across a *realistic* message lifecycle.
//! This example drives the crate's public hot paths in a tight loop so a
//! sampling profiler can attribute time to the stages that dominate in practice:
//! parsing, fsync-bound local delivery, and the IMAP snapshot scan.
//!
//! It is deterministic and self-contained: every iteration delivers the same
//! representative message into a fresh `tempfile::tempdir()` store, opens an
//! IMAP snapshot over the growing mailbox, reads the message back, and stores a
//! flag. Nothing touches the network or any global state.
//!
//! Run it directly to print throughput:
//!
//! ```sh
//! SQLX_OFFLINE=true cargo run --release --example profile -- 2000
//! ```
//!
//! Or under a sampling profiler to get a flamegraph of the hot paths:
//!
//! ```sh
//! SQLX_OFFLINE=true cargo flamegraph --example profile -- 2000
//! ```
//!
//! `argv[1]` is the message count (default 2000).

use std::time::Instant;

use epistle::directory_store::DirectoryHandle;
use epistle::imap::command::parse as imap_parse;
use epistle::imap::mailbox::{Flag, Snapshot, render_flags};
use epistle::smtp::address::Address;
use epistle::smtp::command::parse as smtp_parse;
use epistle::smtp::directory::Directory;
use epistle::smtp::line::LineDecoder;
use epistle::smtp::session::AcceptedMessage;
use epistle::storage::{LocalDelivery, MessageCrypto};

/// Default message count when `argv[1]` is absent.
const DEFAULT_MESSAGES: usize = 2000;

/// The recipient account the workload delivers to.
const ACCOUNT: &str = "alice";

/// The recipient address resolving to [`ACCOUNT`].
const RECIPIENT: &str = "alice@example.org";

/// Build a representative raw `.eml`: a small set of realistic headers plus a
/// multi-line plain-text body. Large enough to make header parsing and the
/// line decoder do real work, small enough to keep delivery fsync-bound (the
/// shape of a typical short message).
fn sample_eml() -> Vec<u8> {
	let mut data = Vec::with_capacity(1024);
	data.extend_from_slice(b"Received: from relay.example.net by mx.example.org\r\n");
	data.extend_from_slice(b"From: Sender Name <sender@example.net>\r\n");
	data.extend_from_slice(b"To: Alice <alice@example.org>\r\n");
	data.extend_from_slice(b"Subject: representative profiling message\r\n");
	data.extend_from_slice(b"Date: Mon, 1 Jun 2026 12:00:00 +0000\r\n");
	data.extend_from_slice(b"Message-ID: <profile.0001@example.net>\r\n");
	data.extend_from_slice(b"MIME-Version: 1.0\r\n");
	data.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
	data.extend_from_slice(b"\r\n");
	for _ in 0..16 {
		data.extend_from_slice(b"This is a line of representative body text for the run.\r\n");
	}
	data
}

/// Drive the per-byte / per-command parsers a message exercises before it is
/// accepted: the envelope commands, the recipient address, an IMAP FETCH a
/// client would issue, and the line decoder splitting the raw header block.
fn parse_pass(raw: &[u8]) {
	// Envelope commands (the SMTP transaction that delivered this message).
	let _ = smtp_parse("MAIL FROM:<sender@example.net> SIZE=1024 BODY=8BITMIME");
	let _ = smtp_parse("RCPT TO:<alice@example.org> NOTIFY=SUCCESS,FAILURE");
	// Recipient address parsing (resolution input).
	let _ = Address::parse(RECIPIENT);
	// A representative client FETCH against the delivered message.
	let _ = imap_parse("a1 UID FETCH 1:* (FLAGS BODY[HEADER.FIELDS (FROM TO SUBJECT)])");
	// Decode the raw header block line by line, as the receive path does.
	let head_end = raw
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|p| p + 4)
		.unwrap_or(raw.len());
	let mut decoder = LineDecoder::new();
	decoder.feed(&raw[..head_end]);
	while let Ok(Some(line)) = decoder.next_line() {
		std::hint::black_box(line);
	}
}

/// Build the in-memory directory mapping [`RECIPIENT`] to [`ACCOUNT`].
fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[(RECIPIENT.to_string(), ACCOUNT.to_string())],
	))
}

/// One accepted message for the given raw bytes.
fn message(raw: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@example.net".to_string(),
		recipients: vec![RECIPIENT.to_string()],
		data: raw.to_vec(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

fn main() {
	let count: usize = std::env::args()
		.nth(1)
		.and_then(|a| a.parse().ok())
		.unwrap_or(DEFAULT_MESSAGES);

	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::disabled();
	let delivery = LocalDelivery::new(dir.path(), directory()).expect("local delivery");
	let raw = sample_eml();

	println!("profiling {count} messages into {}", dir.path().display());
	let start = Instant::now();

	for _ in 0..count {
		// 1. Parse the envelope/address/command/header hot paths.
		parse_pass(&raw);

		// 2. Local delivery: crash-safe write of one .eml copy (temp + fsync +
		//    rename) into the recipient's INBOX. This is the fsync-bound stage.
		let delivered = delivery
			.deliver_routed(&message(&raw), None)
			.expect("deliver");
		std::hint::black_box(&delivered);

		// 3. IMAP snapshot: scan the mailbox directory and read the newest
		//    message back, the access path a client FETCH walks. Snapshot::open
		//    cost grows with the mailbox size, so it is profiled over a mailbox
		//    that grows by one message per iteration.
		let mut snapshot = Snapshot::open(dir.path(), ACCOUNT, "INBOX", &crypto).expect("snapshot");
		let seq = snapshot.len() as u32;
		let last = snapshot.by_sequence(seq).expect("last message");
		let body = snapshot.read(last).expect("read body");
		std::hint::black_box(body.len());

		// 4. STORE \Seen on the just-read message (the path #237's no-op skip
		//    and render_flags touch), then render the response flag list.
		let stored = snapshot
			.store_flags(seq, vec![Flag::Seen])
			.expect("store flags");
		std::hint::black_box(render_flags(stored));
	}

	let elapsed = start.elapsed();
	let secs = elapsed.as_secs_f64();
	let rate = count as f64 / secs;
	println!("delivered {count} messages in {elapsed:.3?} ({rate:.0} msgs/sec)");
}
