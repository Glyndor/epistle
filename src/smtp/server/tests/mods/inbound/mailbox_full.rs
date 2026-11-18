//! `[smtp] mailbox_full`: the same answer at `RCPT TO` and at the end of
//! DATA.

use super::*;
use crate::smtp::directory::Directory;
use crate::smtp::server::{DirectoryHandle, MessageSink, Server};

/// A server whose only mailbox, bob's, holds `used` of its 100 bytes.
fn full(sink: &Arc<MemorySink>, used: u64) -> Server {
	let directory = Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	)
	.with_account_quotas([("bob".to_string(), 100)]);
	let quota = crate::smtp::quota::MailboxQuota::new(move |_| used, 1 << 30);
	Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(DirectoryHandle::new(directory))
		.with_quota(Arc::new(quota))
}

const PERMANENT: &str = "[smtp]\nmailbox_full = \"permanent\"\n";

#[tokio::test]
async fn a_full_mailbox_is_temporary_at_rcpt_by_default() {
	let sink = Arc::new(MemorySink::new());
	let run = deliver_to(full(&sink, 100), &sink, &["bob@example.org"]).await;
	assert!(
		run.output.contains("452 4.2.2 mailbox full"),
		"{}",
		run.output
	);
	assert!(!run.output.contains("552"), "{}", run.output);
}

#[tokio::test]
async fn a_full_mailbox_is_permanent_at_rcpt_when_the_operator_says_so() {
	let sink = Arc::new(MemorySink::new());
	let server = full(&sink, 100).with_inbound_policy(policy(PERMANENT));
	let run = deliver_to(server, &sink, &["bob@example.org"]).await;
	assert!(
		run.output.contains("552 5.2.2 mailbox full"),
		"{}",
		run.output
	);
	assert!(!run.output.contains("452"), "{}", run.output);
}

#[tokio::test]
async fn the_end_of_data_agrees_with_rcpt() {
	// 95 of 100 bytes used: the recipient is accepted, the message does not
	// fit, and the whole message is refused the way a full mailbox is.
	let temporary = Arc::new(MemorySink::new());
	let run = deliver_to(full(&temporary, 95), &temporary, &["bob@example.org"]).await;
	assert!(
		run.output.contains("452 4.2.2 mailbox full"),
		"{}",
		run.output
	);
	let permanent = Arc::new(MemorySink::new());
	let server = full(&permanent, 95).with_inbound_policy(policy(PERMANENT));
	let run = deliver_to(server, &permanent, &["bob@example.org"]).await;
	assert!(
		run.output.contains("552 5.2.2 mailbox full"),
		"{}",
		run.output
	);
	assert!(!run.output.contains("452"), "{}", run.output);
	assert!(run.messages.is_empty());
}

#[test]
fn a_refusal_from_the_store_follows_the_setting_too() {
	use crate::config::MailboxFull;
	use crate::smtp::sink::SinkError;
	let error = SinkError::MailboxFull("bob@example.org".to_string());
	assert!(error.smtp_reply().to_string().starts_with("452 4.2.2"));
	let permanent = error.smtp_reply_with(MailboxFull::Permanent).to_string();
	assert!(permanent.starts_with("552 5.2.2"), "{permanent}");
}
