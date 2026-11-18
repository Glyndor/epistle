//! A signer that is gone, or answers what it should not, leaves the
//! client with [`RemoteError::Unavailable`] and an error in the log, never
//! with the in-process "not signed" outcome.

use std::future::Future;
use std::time::Duration;

use tokio::net::UnixListener;

use super::*;
use crate::dkim::test_support::{GOLDEN, fixed_signer};
use crate::dkim::{HeaderBlock, Refusal};

/// A stand-in for the signer that treats every connection with `behave`.
fn fake_signer<F, Fut>(behave: F) -> (tempfile::TempDir, PathBuf)
where
	F: Fn(UnixStream) -> Fut + Send + 'static,
	Fut: Future<Output = ()> + Send + 'static,
{
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("fake.sock");
	let listener = UnixListener::bind(&socket).expect("bind");
	tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			tokio::spawn(behave(stream));
		}
	});
	(dir, socket)
}

/// Read the request off `stream`, then write `answer` and close.
async fn answer_with(mut stream: UnixStream, answer: Vec<u8>) {
	let mut request = Vec::new();
	let _ = stream.read_to_end(&mut request).await;
	let _ = stream.write_all(&answer).await;
}

fn answering(answer: Vec<u8>) -> (tempfile::TempDir, PathBuf) {
	fake_signer(move |stream| answer_with(stream, answer.clone()))
}

const FAIL_CLOSED: &str = "must not be sent without its signature";

/// Sign GOLDEN's first message through `socket` and check the outcome is
/// `Unavailable`, with one error line that says the message must not
/// leave unsigned.
async fn assert_fails_closed(case: &str, socket: &std::path::Path) {
	let (events, _guard) = capture();
	let client = RemoteSigner::new(socket).with_deadline(Duration::from_millis(300));
	let outcome = client.sign("example.org", GOLDEN[0].0.as_bytes()).await;
	assert!(
		matches!(outcome, Err(RemoteError::Unavailable(_))),
		"{case}: {outcome:?}"
	);
	// The client's line; the signer may log its own side as well.
	let errors = messages(&events, tracing::Level::ERROR);
	let client_lines = errors
		.iter()
		.filter(|line| line.contains(FAIL_CLOSED))
		.count();
	assert_eq!(client_lines, 1, "{case}: {errors:?}");
}

#[tokio::test]
async fn a_missing_or_dead_signer_fails_closed_and_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_fails_closed("no socket at all", &dir.path().join("absent.sock")).await;

	let running = start_with(fixed_signer(dir.path()));
	let client = RemoteSigner::new(&running.socket);
	assert_eq!(
		client
			.sign("example.org", GOLDEN[0].0.as_bytes())
			.await
			.as_deref(),
		Ok(GOLDEN[0].1),
		"the same client signs while the signer runs"
	);
	running.task.abort();
	let _ = running.task.await;
	assert!(
		running.socket.exists(),
		"the socket file outlives the signer"
	);
	assert_fails_closed("a socket nobody listens on", &running.socket).await;
}

#[tokio::test]
async fn an_answer_the_client_cannot_trust_fails_closed() {
	let signed = |text: &str| SignResponse::Signed(text.into()).encode();
	let mut over_cap = u32::MAX.to_be_bytes().to_vec();
	over_cap.extend_from_slice(&[VERSION, 0]);
	let cases: Vec<(&str, (tempfile::TempDir, PathBuf))> = vec![
		("closed without an answer", answering(Vec::new())),
		(
			"an answer cut short",
			answering(vec![0, 0, 0, 100, VERSION, 0, 0]),
		),
		("an answer over the cap", answering(over_cap)),
		(
			"an answer of another version",
			answering(framed(&body(9, 0, &[b"x"]))),
		),
		(
			"a field smuggled after the signature",
			answering(signed("DKIM-Signature: v=1\r\nBcc: x@example.net\r\n")),
		),
		(
			"a blank line that ends the header block",
			answering(signed("DKIM-Signature: v=1\r\n\r\n")),
		),
		("an empty signature", answering(signed(""))),
		(
			"a signature without its CRLF",
			answering(signed("DKIM-Signature: v=1")),
		),
		(
			"a refusal of the frame",
			answering(SignResponse::Refused(Reason::Version).encode()),
		),
		(
			"no answer before the deadline",
			fake_signer(|stream| async move {
				let _held = stream;
				std::future::pending::<()>().await;
			}),
		),
	];
	for (case, (_dir, socket)) in &cases {
		assert_fails_closed(case, socket).await;
	}
}

#[tokio::test]
async fn a_refusal_of_the_content_is_not_an_unavailable_signer() {
	let (events, _guard) = capture();
	let (_dir, socket) = answering(SignResponse::Refused(Reason::Domain).encode());
	let outcome = RemoteSigner::new(&socket)
		.sign("example.org", GOLDEN[0].0.as_bytes())
		.await;
	assert_eq!(outcome, Err(RemoteError::Refused(Reason::Domain)));
	assert!(messages(&events, tracing::Level::ERROR).is_empty());
	assert_eq!(messages(&events, tracing::Level::WARN).len(), 1);

	let (_dir, socket) = answering(SignResponse::Signed(GOLDEN[0].1.into()).encode());
	let outcome = RemoteSigner::new(&socket)
		.sign("example.org", GOLDEN[0].0.as_bytes())
		.await;
	assert_eq!(
		outcome.as_deref(),
		Ok(GOLDEN[0].1),
		"a well-formed answer is taken"
	);
}

/// A key holder that panics while signing.
struct Panicking;

impl KeyHolder for Panicking {
	fn sign_block(&self, _domain: &str, _block: &HeaderBlock) -> Result<String, Refusal> {
		panic!("the key holder failed");
	}
}

#[tokio::test]
async fn a_holder_that_fails_while_signing_leaves_the_client_unavailable() {
	let running = start_with(Panicking);
	assert_fails_closed("the holder panicked", &running.socket).await;
}

#[tokio::test]
async fn an_unreadable_message_never_reaches_the_signer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let client = RemoteSigner::new(dir.path().join("absent.sock"));
	let two_froms = b"From: a@example.org\r\nFrom: b@example.org\r\n\r\nbody\r\n";
	assert_eq!(
		client.sign("example.org", two_froms).await,
		Err(RemoteError::Unreadable),
		"refused before any connection, so the missing socket is not the reason"
	);
}
