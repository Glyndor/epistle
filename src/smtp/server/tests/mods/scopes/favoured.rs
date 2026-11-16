//! An allow entry never overrides authentication: it only skips the
//! score-based screens, and only for a sender this server verified.

use super::*;

const ALLOW: &str = "[antispam.senders]\nallow = [\"partner.example.net\"]\n";
const PASS: &str = "v=spf1 ip4:192.0.2.0/24 -all";
const REJECT: &str = "v=DMARC1; p=reject";
const MONITOR: &str = "v=DMARC1; p=none";

/// Deliver `data` from `envelope` through a server that scores everything
/// as spam, with `scopes` and the DNS `records`.
async fn deliver(
	scopes: Option<&str>,
	records: &[(&str, &str)],
	envelope: &str,
	data: &str,
) -> Run {
	let sink = Arc::new(MemorySink::new());
	let server = server(&sink, scopes.map(super::scopes))
		.with_spf(dns(records))
		.with_bayes(Arc::new(SpamScorer))
		.with_bayes_thresholds(0.9, None);
	run(server, &sink, &script(envelope, &["bob@example.org"], data)).await
}

fn mailbox(run: &Run) -> Option<&str> {
	assert_eq!(run.messages.len(), 1, "delivered once: {}", run.output);
	run.messages[0].mailbox.as_deref()
}

#[tokio::test]
async fn control_without_the_list_a_spam_score_goes_to_junk() {
	let run = deliver(
		None,
		&[("partner.example.net", PASS)],
		"a@partner.example.net",
		&plain("a@partner.example.net"),
	)
	.await;
	assert_eq!(mailbox(&run), Some("Junk"));
}

#[tokio::test]
async fn a_listed_sender_the_server_verified_skips_the_score() {
	let run = deliver(
		Some(ALLOW),
		&[("partner.example.net", PASS)],
		"a@partner.example.net",
		&plain("a@partner.example.net"),
	)
	.await;
	assert_eq!(mailbox(&run), None, "{}", run.output);
}

#[tokio::test]
async fn a_listed_sender_nobody_verified_still_goes_to_junk() {
	// No SPF record at all: the envelope sender is a claim, not a fact.
	let run = deliver(
		Some(ALLOW),
		&[],
		"a@partner.example.net",
		&plain("a@partner.example.net"),
	)
	.await;
	assert_eq!(mailbox(&run), Some("Junk"));
}

#[tokio::test]
async fn a_listed_sender_that_fails_spf_is_refused_not_favoured() {
	let run = deliver(
		Some(ALLOW),
		&[("partner.example.net", "v=spf1 ip4:203.0.113.0/24 -all")],
		"a@partner.example.net",
		&plain("a@partner.example.net"),
	)
	.await;
	assert!(
		run.output.contains(
			"550 5.7.23 SPF validation failed for 192.0.2.7 as sender of partner.example.net"
		),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
}

#[tokio::test]
async fn a_listed_sender_forged_as_a_domain_that_publishes_reject_fails_dmarc() {
	// The envelope is the listed partner, and passes SPF; the From header
	// is a domain that publishes `p=reject` and never sent this.
	let run = deliver(
		Some(ALLOW),
		&[
			("partner.example.net", PASS),
			("_dmarc.victim.example.com", REJECT),
		],
		"a@partner.example.net",
		&plain("boss@victim.example.com"),
	)
	.await;
	assert!(
		run.output
			.contains("550 5.7.1 rejected by DMARC policy of victim.example.com"),
		"{}",
		run.output
	);
	assert!(run.messages.is_empty());
}

#[tokio::test]
async fn a_listed_envelope_with_a_from_of_another_organisation_is_not_favoured() {
	// DMARC publishes `p=none`, so nothing refuses the message; but the
	// listed address only borrows the envelope, so the score still counts.
	let run = deliver(
		Some(ALLOW),
		&[
			("partner.example.net", PASS),
			("_dmarc.victim.example.com", MONITOR),
		],
		"a@partner.example.net",
		&plain("boss@victim.example.com"),
	)
	.await;
	assert_eq!(mailbox(&run), Some("Junk"), "{}", run.output);
}

#[tokio::test]
async fn a_deny_entry_wins_over_an_allow_entry_of_another_scope() {
	let both = "[antispam.senders]\nallow = [\"partner.example.net\"]\n\
		[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny = [\"partner.example.net\"]\n";
	let run = deliver(
		Some(both),
		&[("partner.example.net", PASS)],
		"a@partner.example.net",
		&plain("a@partner.example.net"),
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
async fn two_recipients_favour_the_sender_only_when_both_scopes_do() {
	let one_domain = "[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\nallow = [\"partner.example.net\"]\n";
	let sink = Arc::new(MemorySink::new());
	let server = server(&sink, Some(super::scopes(one_domain)))
		.with_spf(dns(&[("partner.example.net", PASS)]))
		.with_bayes(Arc::new(SpamScorer))
		.with_bayes_thresholds(0.9, None);
	let both = script(
		"a@partner.example.net",
		&["bob@example.org", "carol@example.com"],
		&plain("a@partner.example.net"),
	);
	let run = run(server, &sink, &both).await;
	// carol's domain does not list the sender, so the message is judged
	// as it would be without the list.
	assert_eq!(mailbox(&run), Some("Junk"), "{}", run.output);
}
