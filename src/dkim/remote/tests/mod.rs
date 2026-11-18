//! Tests of signing across the socket: the frame, the server's checks,
//! the deadline and the client's refusal to treat a missing signer as
//! "not signed".

pub use super::*;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::cli::trace::capture::{Capture, CapturedEvent, keep_callsites_live};
use crate::dkim::KeyHolder;
use crate::dkim::remote::frame::{SignResponse, VERSION};

mod codec;
mod down;
mod hostile;
mod permissions;
mod same_bytes;
mod slow;

/// A signer serving on a socket inside a fresh temporary directory.
pub(super) struct Running {
	/// Keeps the directory alive for the test.
	pub(super) _dir: tempfile::TempDir,
	pub(super) socket: PathBuf,
	pub(super) task: tokio::task::JoinHandle<()>,
}

/// Bind `server` at `<tempdir>/signer/dkim.sock` and serve on it.
pub(super) fn start(server: SignerServer) -> Running {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("signer").join("dkim.sock");
	let listener = bind(&socket).expect("bind the signer socket");
	let task = tokio::spawn(server.serve(listener));
	Running {
		_dir: dir,
		socket,
		task,
	}
}

/// A server with `holder`, the default limits, already serving.
pub(super) fn start_with(holder: impl KeyHolder + 'static) -> Running {
	start(SignerServer::new(Arc::new(holder)))
}

/// Write `bytes` as they are, close the write half, and read whatever the
/// signer answers until it closes.
pub(super) async fn raw_exchange(socket: &std::path::Path, bytes: &[u8]) -> Vec<u8> {
	let mut stream = UnixStream::connect(socket).await.expect("connect");
	// The signer may answer and close before reading everything (an
	// oversized frame); a failed write then is part of the exchange.
	let _ = stream.write_all(bytes).await;
	let _ = stream.shutdown().await;
	let mut answer = Vec::new();
	let _ = stream.read_to_end(&mut answer).await;
	answer
}

/// Decode an answer frame as the client would, length prefix included.
pub(super) fn decode_answer(frame: &[u8]) -> SignResponse {
	let (prefix, body) = frame.split_at(4);
	assert_eq!(
		usize::try_from(u32::from_be_bytes(prefix.try_into().expect("prefix"))).expect("len"),
		body.len(),
		"the length prefix names the body"
	);
	SignResponse::decode(body).expect("a well-formed answer")
}

/// A request body built field by field: the version, the operation, and
/// each field with its 4-byte length.
pub(super) fn body(version: u8, operation: u8, fields: &[&[u8]]) -> Vec<u8> {
	let mut body = vec![version, operation];
	for field in fields {
		body.extend_from_slice(&u32::try_from(field.len()).expect("len").to_be_bytes());
		body.extend_from_slice(field);
	}
	body
}

/// `body` with its length prefix.
pub(super) fn framed(body: &[u8]) -> Vec<u8> {
	let mut frame = u32::try_from(body.len())
		.expect("len")
		.to_be_bytes()
		.to_vec();
	frame.extend_from_slice(body);
	frame
}

/// The fields of a well-formed request for [`PLAIN`](crate::dkim::test_support::PLAIN).
pub(super) fn plain_fields() -> (String, String, [u8; 32]) {
	let block = crate::dkim::HeaderBlock::from_message(crate::dkim::test_support::PLAIN.as_bytes())
		.expect("block");
	(block.names, block.canonical, block.body_hash)
}

/// Record every event on this thread until the guard is dropped. The
/// tests run on Tokio's current-thread runtime, so the client and the
/// server tasks log on this thread.
pub(super) fn capture() -> (
	Arc<Mutex<Vec<CapturedEvent>>>,
	tracing::subscriber::DefaultGuard,
) {
	use tracing_subscriber::layer::SubscriberExt;
	keep_callsites_live();
	let capture = Capture::default();
	let events = capture.events.clone();
	let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(capture));
	(events, guard)
}

/// The messages of the captured events at `level`.
pub(super) fn messages(
	events: &Arc<Mutex<Vec<CapturedEvent>>>,
	level: tracing::Level,
) -> Vec<String> {
	events
		.lock()
		.expect("capture")
		.iter()
		.filter(|event| event.level == level)
		.filter_map(|event| event.fields.get("message").cloned())
		.collect()
}
