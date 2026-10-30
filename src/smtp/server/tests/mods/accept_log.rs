//! The log line that records an accepted inbound message.
//!
//! An operator diagnosing "my mail did not arrive" looks at the log
//! first. Before this line existed, an accepted message left nothing
//! there at the default level: the Maildir showed the message
//! afterwards and the metrics showed a counter, but the log could not
//! say whether mail had arrived at all.
//!
//! The line carries no personal data: the account appears as its log
//! pseudonym (`acct-<12 hex>`), never as a name and never as an
//! address. The failure messages name the property and the field, never
//! the captured text, so a failing run does not print the address
//! either.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::layer::SubscriberExt;

use super::*;
use crate::smtp::sink::MemorySink;

/// The message the client sends.
const SCRIPT: &[u8] = b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	))
}

/// The captured events whose `result` field is `value`.
fn with_result<'a>(
	captured: &'a [crate::cli::trace::capture::CapturedEvent],
	value: &str,
) -> Vec<&'a crate::cli::trace::capture::CapturedEvent> {
	captured
		.iter()
		.filter(|event| event.fields.get("result").map(String::as_str) == Some(value))
		.collect()
}

/// An accepted inbound message leaves one INFO line at the default
/// level, with the recipient account as its log pseudonym, the size of
/// the message, the protocol and the outcome. Nothing else: no address
/// and no account name.
#[tokio::test]
async fn an_accepted_message_leaves_one_info_line() {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = crate::cli::trace::capture::Capture::default();
	let events = capture.events.clone();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));

	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory())
		.with_auth_protocol(crate::config::Protocol::Smtp);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(SCRIPT).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("result");

	let messages = sink.messages();
	assert_eq!(messages.len(), 1, "the message was not delivered");

	let captured = std::mem::take(&mut *events.lock().expect("capture"));
	let accepted = with_result(&captured, "accepted");
	assert_eq!(
		accepted.len(),
		1,
		"expected exactly one line about an accepted message"
	);
	let line = accepted[0];
	assert_eq!(
		line.level,
		tracing::Level::INFO,
		"the line must be at the default level"
	);
	assert_eq!(
		line.fields.get("log_id").map(String::as_str),
		Some(crate::log_id::account("bob").as_str()),
		"the line must name the recipient account by its log pseudonym"
	);
	assert_eq!(
		line.fields.get("protocol").map(String::as_str),
		Some("smtp"),
		"the line must name the protocol that carried the message"
	);
	assert_eq!(
		line.fields.get("size").map(String::as_str),
		Some(messages[0].data.len().to_string().as_str()),
		"the line must carry the size of the message that was delivered"
	);
	assert_eq!(
		line.fields.get("recipients").map(String::as_str),
		Some("1"),
		"the line must carry how many recipients the envelope named"
	);
}

/// The line carries no personal data: neither the address of the
/// recipient nor the name of the account it belongs to.
#[tokio::test]
async fn the_accepted_line_carries_no_address_and_no_account_name() {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = crate::cli::trace::capture::Capture::default();
	let events = capture.events.clone();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));

	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory())
		.with_auth_protocol(crate::config::Protocol::Smtp);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(SCRIPT).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("result");

	let captured = std::mem::take(&mut *events.lock().expect("capture"));
	let accepted = with_result(&captured, "accepted");
	assert_eq!(
		accepted.len(),
		1,
		"expected exactly one line about an accepted message"
	);
	let blob: String = accepted[0]
		.fields
		.values()
		.cloned()
		.collect::<Vec<String>>()
		.join("\n");
	assert!(
		!blob.contains("bob@example.org"),
		"the line about an accepted message leaked the recipient address"
	);
	assert!(
		!blob.contains("alice@example.org"),
		"the line about an accepted message leaked the sender address"
	);
	assert!(
		!blob.contains("bob"),
		"the line about an accepted message leaked the account name"
	);
}

/// A message the server refuses leaves no line about an acceptance:
/// the line says what the server did, and a refusal is not an
/// acceptance.
#[tokio::test]
async fn a_refused_message_leaves_no_line_about_an_acceptance() {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = crate::cli::trace::capture::Capture::default();
	let events = capture.events.clone();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));

	let sink = Arc::new(MemorySink::new());
	// A recipient that does not resolve: the server refuses it.
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(DirectoryHandle::new(Directory::default()))
		.with_auth_protocol(crate::config::Protocol::Smtp);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let (mut read, mut write) = tokio::io::split(client);
	write
		.write_all(
			b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<ghost@example.org>\r\n\
QUIT\r\n",
		)
		.await
		.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("result");

	let captured = std::mem::take(&mut *events.lock().expect("capture"));
	assert!(
		with_result(&captured, "accepted").is_empty(),
		"a refused message must not leave a line about an acceptance"
	);
	assert!(
		sink.messages().is_empty(),
		"a refused message must not be delivered"
	);
}
