//! Vacation replies need a verified, addressed message; the Sieve script must belong to the account.

use super::guard::{delivery, enable, raw, replies, sieve, text};

#[test]
fn a_sieve_from_the_account_does_not_own_is_ignored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	sieve(
		dir.path(),
		"vacation :from \"ceo@elsewhere.example\" \"Away.\";",
	);
	let sent = replies(&d, "carol@example.net");
	let reply = text(&sent[0]);
	assert!(reply.contains("From: <alice@example.org>"), "{reply}");
	assert!(!reply.contains("ceo@elsewhere.example"), "{reply}");
	assert_eq!(replies(&d, "dave@example.net").len(), 1);
	sieve(dir.path(), "vacation :from \"al@example.org\" \"Away.\";");
	let sent = replies(&d, "erin@example.net");
	assert!(
		text(&sent[0]).contains("From: <al@example.org>"),
		"own address kept"
	);
}

#[test]
fn no_reply_to_a_sender_the_server_did_not_verify() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let headers = "To: alice@example.org\r\nSubject: hi";
	let forged = raw("carol@example.net", &["alice@example.org"], headers, false);
	let sent = d.deliver_routed(&forged, None).expect("deliver").replies;
	assert!(
		sent.is_empty(),
		"an unverified envelope sender gets nothing"
	);
	let verified = raw("carol@example.net", &["alice@example.org"], headers, true);
	let sent = d.deliver_routed(&verified, None).expect("deliver").replies;
	assert_eq!(sent.len(), 1, "control");
}

#[test]
fn sieve_vacation_also_needs_a_verified_and_addressed_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	sieve(dir.path(), "vacation \"Away.\";");
	let unverified = raw(
		"carol@example.net",
		&["alice@example.org"],
		"To: alice@example.org",
		false,
	);
	assert!(
		d.deliver_routed(&unverified, None)
			.expect("deliver")
			.replies
			.is_empty()
	);
	let blind = raw(
		"dave@example.net",
		&["alice@example.org"],
		"To: list@example.net",
		true,
	);
	assert!(
		d.deliver_routed(&blind, None)
			.expect("deliver")
			.replies
			.is_empty()
	);
	let addressed = raw(
		"erin@example.net",
		&["alice@example.org"],
		"Cc: alice@example.org",
		true,
	);
	assert_eq!(
		d.deliver_routed(&addressed, None)
			.expect("deliver")
			.replies
			.len(),
		1
	);
}

#[test]
fn reply_only_when_an_own_address_is_in_to_or_cc() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let cases = [
		("To: team@example.net", false),
		("Bcc: alice@example.org", false),
		("Reply-To: alice@example.org", false),
		("To: xalice@example.org", false),
		("To: alice@example.org.evil.example", false),
		("To: <alice@example.orgx>", false),
		("Subject: alice@example.org", false),
		("To: Alice <alice@example.org>", true),
		("To: someone@example.net,\r\n ALICE@Example.Org", true),
		("Cc: \"Al\" <al@example.org>", true),
		(
			"To: a@example.net\r\nCc: b@example.net, alice@example.org",
			true,
		),
	];
	for (index, (headers, expected)) in cases.iter().enumerate() {
		let sender = format!("sender{index}@example.net");
		let message = raw(&sender, &["alice@example.org"], headers, true);
		let sent = d.deliver_routed(&message, None).expect("deliver").replies;
		assert_eq!(sent.len(), usize::from(*expected), "{headers:?}");
	}
}

#[test]
fn a_huge_to_header_costs_linear_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let d = delivery(dir.path());
	enable(dir.path(), "Away.");
	let headers = format!("To: {}", "alice@example.or".repeat(1 << 16));
	let message = raw("carol@example.net", &["alice@example.org"], &headers, true);
	let started = std::time::Instant::now();
	let sent = d.deliver_routed(&message, None).expect("deliver").replies;
	assert!(sent.is_empty(), "no full own address in the header");
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
