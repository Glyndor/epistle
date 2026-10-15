//! `clamd_on_error = "defer"` over SMTP: a clamd that cannot scan answers
//! `451 4.7.1` at the end of DATA, inbound and on submission, and nothing
//! reaches a mailbox or the queue unscanned.

use tokio::io::AsyncWriteExt;

use super::tests_auth::{directory_with_password, reply};
use super::tests_virus::submit;
use super::*;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::submission_scan::ScanningSink;
use crate::config::ClamdOnError;
use crate::smtp::sink::MemorySink;

const DEFERRED: &str = "451 4.7.1 content scan unavailable, try again later\r\n";

const INBOUND: &str =
	"From: x@example.net\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nhello\r\n";

/// A clamd hook whose socket does not exist, so every scan fails.
fn down(dir: &std::path::Path, on_error: ClamdOnError) -> Arc<ClamdHook> {
	Arc::new(ClamdHook::new(dir.join("clamd.sock")).with_on_error(on_error))
}

/// Deliver [`INBOUND`] from an unauthenticated client with `hook` as the
/// scanner; the reply to the end of DATA and what reached the sink.
async fn deliver(hook: Arc<ClamdHook>) -> (String, usize) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone())
		.with_directory(directory_with_password())
		.with_hook(hook);
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(
			b"EHLO c.example.net\r\nMAIL FROM:<x@example.net>\r\nRCPT TO:<alice@example.org>\r\nDATA\r\n",
		)
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut client).await);
	}
	client
		.write_all(format!("{INBOUND}.\r\n").as_bytes())
		.await
		.expect("data");
	let answer = reply(&mut client).await;
	client.write_all(b"QUIT\r\n").await.expect("quit");
	let _ = reply(&mut client).await;
	drop(client);
	task.await.expect("server task").expect("server result");
	(answer, sink.messages().len())
}

#[tokio::test]
async fn inbound_mail_is_deferred_while_clamd_cannot_scan() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (answer, delivered) = deliver(down(dir.path(), ClamdOnError::Defer)).await;
	assert_eq!(answer, DEFERRED);
	assert_eq!(delivered, 0, "nothing delivered unscanned");
}

#[tokio::test]
async fn inbound_mail_is_accepted_unscanned_by_default() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (answer, delivered) = deliver(down(dir.path(), ClamdOnError::Accept)).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered, 1);
}

#[tokio::test]
async fn a_submission_is_deferred_while_clamd_cannot_scan() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inner = Arc::new(MemorySink::new());
	let sink = ScanningSink::wrap(
		true,
		inner.clone(),
		Some(down(dir.path(), ClamdOnError::Defer)),
		None,
		None,
	)
	.expect("sink");
	let answer = submit(
		sink,
		"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: s\r\n\r\nhi\r\n",
	)
	.await;
	assert_eq!(answer, DEFERRED);
	assert!(inner.messages().is_empty(), "nothing queued unscanned");
}
