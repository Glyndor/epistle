//! The attachment settings of the recipients' scopes.

use super::*;
use crate::antispam::attachments::policy::Policy;
use crate::config::Attachments;

/// A message with one attachment named `name` of `size` bytes, declared as
/// `kind`.
fn with_attachment(name: &str, kind: &str, size: usize) -> String {
	use base64::Engine;
	let body = base64::engine::general_purpose::STANDARD.encode(vec![b'x'; size]);
	let wrapped: Vec<String> = body
		.as_bytes()
		.chunks(76)
		.map(|line| String::from_utf8_lossy(line).into_owned())
		.collect();
	format!(
		"From: a@example.net\r\nTo: bob@example.org\r\nSubject: file\r\nMIME-Version: 1.0\r\n\
		 Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
		 --b\r\nContent-Type: {kind}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\n\
		 Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
		wrapped.join("\r\n")
	)
}

fn policy() -> Arc<Policy> {
	let section = Attachments {
		mode: crate::config::AttachmentMode::Flag,
		..Attachments::default()
	};
	Arc::new(Policy::from_config(&section, 1 << 20).expect("on"))
}

async fn deliver(scopes: &str, recipients: &[&str], data: &str) -> Run {
	let sink = Arc::new(MemorySink::new());
	let server = server(&sink, Some(super::scopes(scopes))).with_attachment_policy(policy());
	run(server, &sink, &script("a@example.net", recipients, data)).await
}

const BOB_REJECTS: &str = "[attachments]\nmode = \"flag\"\n\
	[[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.attachments]\nmode = \"reject\"\n\
	max_attachment_bytes = 1000\nblock_extensions = [\"docm\"]\nblock_mime_types = [\"audio/*\"]\n";

#[tokio::test]
async fn control_a_small_plain_attachment_is_delivered_untouched() {
	let run = deliver(
		BOB_REJECTS,
		&["bob@example.org"],
		&with_attachment("a.txt", "text/plain", 100),
	)
	.await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
	let text = String::from_utf8_lossy(&run.messages[0].data).into_owned();
	assert!(!text.contains("X-Epistle-Attachment-Warning"), "{text}");
}

#[tokio::test]
async fn an_attachment_over_the_cap_of_the_account_is_refused() {
	let run = deliver(
		BOB_REJECTS,
		&["bob@example.org"],
		&with_attachment("a.txt", "text/plain", 2000),
	)
	.await;
	assert!(
		run.output
			.contains("550 5.7.1 attachment type not accepted"),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
}

#[tokio::test]
async fn the_cap_of_one_account_does_not_reach_another() {
	// alice's scope is the server's: flag, and no cap.
	let run = deliver(
		BOB_REJECTS,
		&["alice@example.org"],
		&with_attachment("a.txt", "text/plain", 2000),
	)
	.await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
}

#[tokio::test]
async fn a_scope_extension_and_mime_type_are_findings() {
	for (name, kind) in [("macro.docm", "text/plain"), ("song.txt", "audio/mpeg")] {
		let run = deliver(
			BOB_REJECTS,
			&["bob@example.org"],
			&with_attachment(name, kind, 100),
		)
		.await;
		assert!(
			run.output
				.contains("550 5.7.1 attachment type not accepted"),
			"{name}: {}",
			run.output
		);
	}
}

#[tokio::test]
async fn the_strictest_recipient_decides_for_the_message() {
	let run = deliver(
		BOB_REJECTS,
		&["alice@example.org", "bob@example.org"],
		&with_attachment("a.txt", "text/plain", 2000),
	)
	.await;
	assert!(
		run.output
			.contains("550 5.7.1 attachment type not accepted"),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
}

#[tokio::test]
async fn an_attachment_exactly_at_the_cap_is_accepted_and_one_byte_more_is_not() {
	let at = deliver(
		BOB_REJECTS,
		&["bob@example.org"],
		&with_attachment("a.txt", "text/plain", 1000),
	)
	.await;
	assert_eq!(at.messages.len(), 1, "{}", at.output);
	let over = deliver(
		BOB_REJECTS,
		&["bob@example.org"],
		&with_attachment("a.txt", "text/plain", 1001),
	)
	.await;
	assert!(
		over.output
			.contains("550 5.7.1 attachment type not accepted"),
		"{}",
		over.output
	);
}

#[tokio::test]
async fn an_alias_gets_the_strictest_attachment_policy_of_its_members() {
	let sink = Arc::new(MemorySink::new());
	let server = super::refusals::with_team(&sink, BOB_REJECTS).with_attachment_policy(policy());
	let run = run(
		server,
		&sink,
		&script(
			"a@example.net",
			&["team@example.org"],
			&with_attachment("a.txt", "text/plain", 2000),
		),
	)
	.await;
	assert!(
		run.output
			.contains("550 5.7.1 attachment type not accepted"),
		"{}",
		run.output
	);
}
