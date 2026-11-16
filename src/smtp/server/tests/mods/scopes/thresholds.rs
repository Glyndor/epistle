//! The Bayesian thresholds and the greylist delay of a scope, on the wire.

use super::*;
use crate::antispam::greylist::MemoryGreylist;

/// A server that scores everything 0.99 with the server junk threshold at
/// `junk_at`, and the scopes in `extra`.
fn spam_server(
	sink: &Arc<MemorySink>,
	extra: &str,
	junk_at: f64,
	reject_at: Option<f64>,
) -> Server {
	server(sink, Some(scopes(extra)))
		.with_bayes(Arc::new(SpamScorer))
		.with_bayes_thresholds(junk_at, reject_at)
}

async fn deliver(server: Server, sink: &Arc<MemorySink>, recipients: &[&str]) -> Run {
	run(
		server,
		sink,
		&script("a@example.net", recipients, &plain("a@example.net")),
	)
	.await
}

#[tokio::test]
async fn control_the_server_threshold_leaves_a_score_below_it_in_the_inbox() {
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, "", 0.995, None),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
	assert_eq!(run.messages[0].mailbox, None);
}

#[tokio::test]
async fn a_domain_threshold_junks_what_the_server_threshold_lets_through() {
	let scope = "[[antispam_scope]]\ndomain = \"example.org\"\nbayes_junk_at = 0.9\n";
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.995, None),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert_eq!(
		run.messages[0].mailbox.as_deref(),
		Some("Junk"),
		"{}",
		run.output
	);
	// Another domain keeps the server's threshold.
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.995, None),
		&sink,
		&["carol@example.com"],
	)
	.await;
	assert_eq!(run.messages[0].mailbox, None, "{}", run.output);
}

#[tokio::test]
async fn an_account_threshold_reaches_that_account_only() {
	let scope = "[[antispam_scope]]\naccount = \"bob\"\nbayes_junk_at = 0.9\n";
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.995, None),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert_eq!(run.messages[0].mailbox.as_deref(), Some("Junk"));
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.995, None),
		&sink,
		&["alice@example.org"],
	)
	.await;
	assert_eq!(run.messages[0].mailbox, None);
}

#[tokio::test]
async fn a_domain_reject_threshold_refuses_during_data() {
	let scope = "[[antispam_scope]]\ndomain = \"example.com\"\nbayes_reject_at = 0.98\n";
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.9, None),
		&sink,
		&["carol@example.com"],
	)
	.await;
	assert!(
		run.output.contains("550 5.7.1 message rejected as spam"),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
	// The same score for another domain is only junked.
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.9, None),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert_eq!(run.messages[0].mailbox.as_deref(), Some("Junk"));
}

#[tokio::test]
async fn the_strictest_recipient_decides_when_the_message_has_two() {
	let scope = "[[antispam_scope]]\ndomain = \"example.com\"\nbayes_junk_at = 0.9\n";
	let sink = Arc::new(MemorySink::new());
	let run = deliver(
		spam_server(&sink, scope, 0.995, None),
		&sink,
		&["bob@example.org", "carol@example.com"],
	)
	.await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
	assert_eq!(run.messages[0].mailbox.as_deref(), Some("Junk"));
}

fn greylisting(sink: &Arc<MemorySink>, extra: &str) -> Server {
	server(sink, Some(scopes(extra))).with_greylist(Arc::new(MemoryGreylist::new()), 0)
}

#[tokio::test]
async fn a_domain_greylists_where_the_server_does_not() {
	let scope = "[[antispam_scope]]\ndomain = \"example.com\"\ngreylist_delay_secs = 600\n";
	let sink = Arc::new(MemorySink::new());
	let run = deliver(greylisting(&sink, scope), &sink, &["carol@example.com"]).await;
	assert!(
		run.output.contains("451 4.7.1 greylisted"),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
	let sink = Arc::new(MemorySink::new());
	let run = deliver(greylisting(&sink, scope), &sink, &["bob@example.org"]).await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
}

#[tokio::test]
async fn a_domain_can_turn_the_server_greylist_off() {
	let scope = "[[antispam_scope]]\ndomain = \"example.org\"\ngreylist_delay_secs = 0\n";
	let sink = Arc::new(MemorySink::new());
	let server =
		server(&sink, Some(scopes(scope))).with_greylist(Arc::new(MemoryGreylist::new()), 600);
	let run = deliver(server, &sink, &["bob@example.org"]).await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
	// The control: the other domain is greylisted by the server's delay.
	let sink = Arc::new(MemorySink::new());
	let server = super::server(&sink, Some(scopes(scope)))
		.with_greylist(Arc::new(MemoryGreylist::new()), 600);
	let run = deliver(server, &sink, &["carol@example.com"]).await;
	assert!(
		run.output.contains("451 4.7.1 greylisted"),
		"{}",
		run.output
	);
}
