//! The deny lists at `RCPT TO`.

use super::*;

const DENY: &str = "[antispam.senders]\ndeny = [\"*.spam.example.net\", \"bad@example.net\"]\n";

async fn converse(scopes: &str, script: &str) -> Run {
	let sink = Arc::new(MemorySink::new());
	run(server(&sink, Some(super::scopes(scopes))), &sink, script).await
}

#[tokio::test]
async fn a_denied_sender_is_refused_at_rcpt_before_any_data() {
	let run = converse(
		DENY,
		"EHLO client.example.org\r\nMAIL FROM:<a@mail.spam.example.net>\r\nRCPT TO:<bob@example.org>\r\nQUIT\r\n",
	)
	.await;
	assert!(
		run.output
			.contains("550 5.7.1 sender not accepted for this recipient"),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
}

#[tokio::test]
async fn a_sender_that_only_resembles_a_denied_domain_is_accepted() {
	for sender in [
		"a@spam.example.net",
		"a@xspam.example.net",
		"a@mail.spam.example.net.example.org",
	] {
		let run = converse(
			DENY,
			&format!(
				"EHLO client.example.org\r\nMAIL FROM:<{sender}>\r\nRCPT TO:<bob@example.org>\r\nQUIT\r\n"
			),
		)
		.await;
		assert!(
			!run.output.contains("5.7.1 sender not accepted"),
			"{sender}: {}",
			run.output
		);
	}
}

#[tokio::test]
async fn the_null_sender_is_never_denied() {
	let run = converse(
		DENY,
		"EHLO client.example.org\r\nMAIL FROM:<>\r\nRCPT TO:<bob@example.org>\r\nQUIT\r\n",
	)
	.await;
	assert!(!run.output.contains("5.7.1"), "{}", run.output);
}

#[tokio::test]
async fn a_domain_deny_refuses_that_recipient_and_leaves_the_others() {
	let scope = "[[antispam_scope]]\ndomain = \"example.com\"\n[antispam_scope.senders]\ndeny = [\"friend.example.net\"]\n";
	let run = converse(
		scope,
		&script(
			"a@friend.example.net",
			&["bob@example.org", "carol@example.com"],
			&plain("a@friend.example.net"),
		),
	)
	.await;
	let replies: Vec<&str> = run.output.lines().collect();
	// bob (example.org) is accepted, carol (example.com) is refused.
	assert!(
		replies
			.iter()
			.any(|line| line.starts_with("550 5.7.1 sender not accepted")),
		"{}",
		run.output
	);
	assert_eq!(run.messages.len(), 1);
	assert_eq!(
		run.messages[0].recipients,
		vec!["bob@example.org".to_string()]
	);
}

#[tokio::test]
async fn an_account_scope_refuses_for_that_account_only() {
	let scope = "[[antispam_scope]]\naccount = \"alice\"\n[antispam_scope.senders]\ndeny = [\"friend.example.net\"]\n";
	let run = converse(
		scope,
		"EHLO client.example.org\r\nMAIL FROM:<a@friend.example.net>\r\nRCPT TO:<alice@example.org>\r\nRCPT TO:<bob@example.org>\r\nQUIT\r\n",
	)
	.await;
	let refused = run.output.matches("550 5.7.1 sender not accepted").count();
	assert_eq!(refused, 1, "{}", run.output);
	assert!(
		run.output.contains("250 2.1.5") || run.output.matches("\r\n250 ").count() >= 3,
		"{}",
		run.output
	);
}

#[tokio::test]
async fn an_unknown_recipient_still_says_no_such_user() {
	let run = converse(
		DENY,
		"EHLO client.example.org\r\nMAIL FROM:<a@mail.spam.example.net>\r\nRCPT TO:<nobody@example.org>\r\nQUIT\r\n",
	)
	.await;
	assert!(
		run.output.contains("550 5.1.1 no such user"),
		"{}",
		run.output
	);
	assert!(
		!run.output.contains("sender not accepted"),
		"{}",
		run.output
	);
}

const ALIAS: &str = "[[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.senders]\ndeny = [\"friend.example.net\"]\n";

/// A server whose `team@example.org` delivers to alice and bob.
pub(super) fn with_team(sink: &Arc<MemorySink>, scopes: &str) -> Server {
	let directory = DirectoryHandle::new(
		Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_aliases([(
			"team@example.org".to_string(),
			crate::smtp::directory::AliasSpec {
				members: vec!["alice@example.org".into(), "bob@example.org".into()],
				senders: Vec::new(),
				hidden: false,
				list_id: None,
			},
		)]),
	);
	Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory)
		.with_scopes(super::scopes(scopes))
}

#[tokio::test]
async fn an_alias_is_refused_when_any_member_denies_the_sender() {
	let sink = Arc::new(MemorySink::new());
	let run = run(
		with_team(&sink, ALIAS),
		&sink,
		"EHLO client.example.org\r\nMAIL FROM:<a@friend.example.net>\r\nRCPT TO:<team@example.org>\r\nQUIT\r\n",
	)
	.await;
	assert!(
		run.output.contains("550 5.7.1 sender not accepted"),
		"{}",
		run.output
	);
	// The control: a sender nobody denies reaches the alias.
	let sink = Arc::new(MemorySink::new());
	let run = super::run(
		with_team(&sink, ALIAS),
		&sink,
		"EHLO client.example.org\r\nMAIL FROM:<a@other.example.net>\r\nRCPT TO:<team@example.org>\r\nQUIT\r\n",
	)
	.await;
	assert!(
		!run.output.contains("sender not accepted"),
		"{}",
		run.output
	);
}

#[tokio::test]
async fn every_spelling_of_a_denied_sender_is_refused() {
	for sender in [
		"A@Mail.Spam.Example.NET",
		"BAD@example.net",
		"a@x.xn--bcher-kva.example",
	] {
		let scope = format!(
			"{DENY}\n[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny = [\"*.bücher.example\"]\n"
		);
		let run = converse(
			&scope,
			&format!(
				"EHLO client.example.org\r\nMAIL FROM:<{sender}>\r\nRCPT TO:<bob@example.org>\r\nQUIT\r\n"
			),
		)
		.await;
		assert!(
			run.output.contains("550 5.7.1 sender not accepted"),
			"{sender}: {}",
			run.output
		);
	}
}
