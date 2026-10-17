//! The attachment policy on inbound SMTP: the exact reply, the mailbox and
//! the warning header for each mode.

use tokio::io::AsyncWriteExt;

use super::tests_auth::{directory_with_password, reply};
use super::*;
use crate::antispam::attachments::policy::Policy;
use crate::config::{AttachmentMode, Attachments, ContentAction};
use crate::smtp::sink::MemorySink;

const EXE_AS_JPG: &str = "From: x@example.net\r\nTo: alice@example.org\r\nSubject: photo\r\n\
	MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
	Content-Type: text/plain\r\n\r\nsee attached\r\n--b\r\n\
	Content-Type: image/jpeg; name=holiday.jpg\r\nContent-Transfer-Encoding: base64\r\n\r\n\
	TVqQAAMAAAAEAAAA\r\n--b--\r\n";

const FORGED: &str = "From: x@example.net\r\nTo: alice@example.org\r\nSubject: hi\r\n\
	X-Epistle-Attachment-Warning: none\r\n\r\nplain text, nothing attached\r\n";

fn policy(mode: AttachmentMode) -> Arc<Policy> {
	let section = Attachments {
		mode,
		macros: ContentAction::Quarantine,
		encrypted_archives: ContentAction::Flag,
		..Attachments::default()
	};
	Arc::new(Policy::from_config(&section, 1 << 20).expect("mode is not off"))
}

/// Deliver `data` from an unauthenticated client; the reply to the end of
/// DATA and what reached the sink.
async fn deliver(policy: Option<Arc<Policy>>, data: &str) -> (String, Vec<AcceptedMessage>) {
	let sink = Arc::new(MemorySink::new());
	let mut server =
		Server::new("mail.example.org", sink.clone()).with_directory(directory_with_password());
	if let Some(policy) = policy {
		server = server.with_attachment_policy(policy);
	}
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
		.write_all(format!("{data}.\r\n").as_bytes())
		.await
		.expect("data");
	let answer = reply(&mut client).await;
	client.write_all(b"QUIT\r\n").await.expect("quit");
	let _ = reply(&mut client).await;
	drop(client);
	task.await.expect("server task").expect("server result");
	(answer, sink.messages())
}

fn warning(message: &AcceptedMessage) -> Vec<String> {
	crate::smtp::trace::header_values(&message.data, "X-Epistle-Attachment-Warning")
}

#[tokio::test]
async fn reject_mode_refuses_a_disguised_executable_during_smtp() {
	let (answer, delivered) = deliver(Some(policy(AttachmentMode::Reject)), EXE_AS_JPG).await;
	assert_eq!(answer, "550 5.7.1 attachment type not accepted\r\n");
	assert!(delivered.is_empty(), "nothing was delivered");
}

#[tokio::test]
async fn quarantine_mode_delivers_to_rejects_with_the_reason_codes() {
	let (answer, delivered) = deliver(Some(policy(AttachmentMode::Quarantine)), EXE_AS_JPG).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered.len(), 1);
	assert_eq!(delivered[0].mailbox.as_deref(), Some("Rejects"));
	assert_eq!(
		warning(&delivered[0]),
		vec!["executable-content, type-mismatch"]
	);
}

#[tokio::test]
async fn flag_mode_delivers_to_the_inbox_with_the_reason_codes() {
	let (answer, delivered) = deliver(Some(policy(AttachmentMode::Flag)), EXE_AS_JPG).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered.len(), 1);
	assert_eq!(delivered[0].mailbox, None);
	assert_eq!(
		warning(&delivered[0]),
		vec!["executable-content, type-mismatch"]
	);
}

#[tokio::test]
async fn a_warning_header_from_the_sender_is_removed() {
	let (answer, delivered) = deliver(Some(policy(AttachmentMode::Quarantine)), FORGED).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered.len(), 1);
	assert!(
		warning(&delivered[0]).is_empty(),
		"the forged header survived"
	);
	assert_eq!(delivered[0].mailbox, None);
}

#[tokio::test]
async fn without_a_policy_the_message_is_untouched() {
	let (answer, delivered) = deliver(None, EXE_AS_JPG).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered[0].mailbox, None);
	assert!(warning(&delivered[0]).is_empty());
}

#[test]
fn off_builds_no_policy() {
	let section = Attachments {
		mode: AttachmentMode::Off,
		..Attachments::default()
	};
	assert!(Policy::from_config(&section, 1024).is_none());
}

#[tokio::test]
async fn an_authenticated_submission_the_policy_stops_is_refused() {
	let inner = Arc::new(MemorySink::new());
	let sink = crate::antispam::submission_scan::ScanningSink::wrap_with_attachments(
		true,
		inner.clone(),
		None,
		Some(policy(AttachmentMode::Quarantine)),
		None,
		None,
	)
	.expect("sink");
	let data = EXE_AS_JPG.replace("x@example.net", "alice@example.org");
	let answer = super::tests_virus::submit(sink, &data).await;
	assert_eq!(answer, "550 5.7.1 attachment type not accepted\r\n");
	assert!(inner.messages().is_empty(), "nothing was routed");
}

#[tokio::test]
async fn a_forged_warning_header_is_removed_also_when_the_policy_is_off() {
	// Only the server speaks in this header. With the inspection off, a
	// sender's copy would read as the server's verdict.
	let forged = FORGED.replace("none", "executable-content");
	let (answer, delivered) = deliver(None, &forged).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered.len(), 1);
	assert_eq!(warning(&delivered[0]), Vec::<String>::new());
}

#[tokio::test]
async fn flag_mode_adds_one_header_and_leaves_every_other_byte_alone() {
	let (_, delivered) = deliver(Some(policy(AttachmentMode::Flag)), EXE_AS_JPG).await;
	let data = &delivered[0].data;
	let header = b"X-Epistle-Attachment-Warning: executable-content, type-mismatch\r\n";
	assert!(data.starts_with(header), "the header is on top");
	let (_, plain) = deliver(None, EXE_AS_JPG).await;
	let rest = &data[header.len()..];
	// The trace headers carry a timestamp, so compare from the original
	// message on: it is byte for byte what the client sent.
	let original = EXE_AS_JPG.as_bytes();
	assert!(
		rest.ends_with(original),
		"the message after it is unchanged"
	);
	assert!(plain[0].data.ends_with(original));
}
