//! A trusted complaint suppresses and counts; what cannot be read or is not
//! ours changes nothing.

use super::*;

fn run(fbl: &Fbl, message: &AcceptedMessage) -> (Outcome, tempfile::TempDir, Metrics) {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Metrics::new();
	let outcome = process(fbl, dir.path(), &directory(), message, Some(&metrics));
	(outcome, dir, metrics)
}

fn assert_untouched(dir: &tempfile::TempDir, metrics: &Metrics) {
	let list = SuppressionList::open(dir.path()).expect("list");
	assert!(list.entries().is_empty());
	assert!(list.entries_for("alice").is_empty());
	assert_eq!(metrics.snapshot()["fbl_complaints"], 0);
}

#[test]
fn a_complaint_about_our_message_suppresses_the_recipient_for_that_account_only() {
	let (outcome, dir, metrics) = run(&fbl(""), &verified(valid_report("Victim@Example.com")));
	assert_eq!(
		outcome,
		Outcome::Counted {
			account: "alice".into(),
			class: MailClass::Transactional
		}
	);
	let list = SuppressionList::open(dir.path()).expect("list");
	assert!(list.is_suppressed_for("alice", "victim@example.com"));
	assert!(!list.is_suppressed_for("bob", "victim@example.com"));
	assert!(
		!list.is_suppressed("victim@example.com"),
		"not the global list"
	);
	let entry = list
		.entry_for("alice", "victim@example.com")
		.expect("entry");
	assert_eq!(
		entry.reason.as_deref(),
		Some("spam complaint via arf.example.net (transactional)")
	);
	assert_eq!(metrics.snapshot()["fbl_complaints"], 1);
	assert_eq!(metrics.fbl_complaints_for("alice", "transactional"), 1);
	assert_eq!(metrics.fbl_complaints_for("alice", "marketing"), 0);
	let text = metrics.render();
	assert!(text.contains(
		"mail_fbl_complaints_by_sender_total{account=\"alice\",class=\"transactional\"} 1"
	));
	assert!(text.contains("mail_fbl_complaints_total 1"));
}

#[test]
fn the_same_report_twice_counts_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Metrics::new();
	let message = verified(valid_report("victim@example.com"));
	let first = process(&fbl(""), dir.path(), &directory(), &message, Some(&metrics));
	let second = process(&fbl(""), dir.path(), &directory(), &message, Some(&metrics));
	assert!(matches!(first, Outcome::Counted { .. }));
	assert_eq!(second, Outcome::Duplicate);
	assert_eq!(metrics.snapshot()["fbl_complaints"], 1);
}

#[test]
fn with_suppression_off_the_complaint_is_counted_and_nothing_is_written() {
	let (outcome, dir, metrics) = run(
		&fbl("fbl_suppress = false"),
		&verified(valid_report("victim@example.com")),
	);
	assert!(matches!(outcome, Outcome::Counted { .. }));
	assert_eq!(metrics.snapshot()["fbl_complaints"], 1);
	let list = SuppressionList::open(dir.path()).expect("list");
	assert!(list.entries_for("alice").is_empty());
	assert!(list.entries().is_empty());
}

#[test]
fn a_malformed_report_changes_nothing_and_is_counted_as_dropped() {
	let mut data = valid_report("victim@example.com");
	let cut = String::from_utf8_lossy(&data)
		.find("--bd--")
		.expect("closing");
	data.truncate(cut);
	let (outcome, dir, metrics) = run(&fbl(""), &verified(data));
	assert_eq!(outcome, Outcome::Unreadable);
	assert_untouched(&dir, &metrics);
	assert_eq!(metrics.snapshot()["reports_dropped"], 1);
}

#[test]
fn a_message_that_is_not_a_feedback_report_changes_nothing() {
	let plain = b"From: fbl@arf.example.net\r\nContent-Type: text/plain\r\n\r\nhello\r\n";
	let (outcome, dir, metrics) = run(&fbl(""), &verified(plain.to_vec()));
	assert_eq!(outcome, Outcome::Unreadable);
	assert_untouched(&dir, &metrics);
	assert_eq!(metrics.snapshot()["reports_dropped"], 0, "not a failure");
}

#[test]
fn the_wrong_content_type_is_not_read() {
	for header in [
		"multipart/mixed; boundary=\"bd\"",
		"multipart/report; report-type=delivery-status; boundary=\"bd\"",
		"multipart/report; boundary=\"bd\"",
	] {
		let data = String::from_utf8(valid_report("victim@example.com"))
			.expect("utf8")
			.replace(
				"multipart/report; report-type=feedback-report; boundary=\"bd\"",
				header,
			);
		let (outcome, dir, metrics) = run(&fbl(""), &verified(data.into_bytes()));
		assert_eq!(outcome, Outcome::Unreadable, "{header}");
		assert_untouched(&dir, &metrics);
	}
}

#[test]
fn an_oversized_report_is_refused_whole() {
	let filler = "X".repeat(mime::MAX_ARF);
	let data = report(
		&complaint_fields("victim@example.com"),
		&format!(
			"{}X-Filler: {filler}\r\n",
			original(
				"alice@example.org",
				"victim@example.com",
				Some("epistle:transactional:example.org")
			)
		),
	);
	assert!(data.len() > mime::MAX_ARF);
	let (outcome, dir, metrics) = run(&fbl(""), &verified(data));
	assert_eq!(outcome, Outcome::Unreadable);
	assert_untouched(&dir, &metrics);
	assert_eq!(metrics.snapshot()["reports_dropped"], 1);
}

#[test]
fn two_machine_readable_parts_are_ambiguous_and_refused() {
	let data = String::from_utf8(valid_report("victim@example.com"))
		.expect("utf8")
		.replace(
			"--bd\r\nContent-Type: message/rfc822",
			"--bd\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\n\
			 Original-Rcpt-To: other@example.com\r\n--bd\r\nContent-Type: message/rfc822",
		);
	let (outcome, dir, metrics) = run(&fbl(""), &verified(data.into_bytes()));
	assert_eq!(outcome, Outcome::Unreadable);
	assert_untouched(&dir, &metrics);
}

#[test]
fn only_a_spam_complaint_with_a_recipient_acts() {
	for fields in [
		"Feedback-Type: not-spam\r\nOriginal-Rcpt-To: victim@example.com\r\n".to_string(),
		"Feedback-Type: virus\r\nOriginal-Rcpt-To: victim@example.com\r\n".to_string(),
		"Feedback-Type: abuse\r\nVersion: 1\r\n".to_string(),
		"Feedback-Type: abuse\r\nOriginal-Rcpt-To: not an address\r\n".to_string(),
		"Version: 1\r\nOriginal-Rcpt-To: victim@example.com\r\n".to_string(),
	] {
		let data = report(
			&fields,
			&original(
				"alice@example.org",
				"victim@example.com",
				Some("epistle:transactional:example.org"),
			),
		);
		let (outcome, dir, metrics) = run(&fbl(""), &verified(data));
		assert_eq!(outcome, Outcome::NotActionable, "{fields}");
		assert_untouched(&dir, &metrics);
	}
}

#[test]
fn a_message_this_server_did_not_send_changes_nothing() {
	const ID: &str = "epistle:transactional:example.org";
	let ours = |from: &str, to: &str, id: Option<&str>| original(from, to, id);
	for quoted in [
		// No Feedback-ID at all.
		ours("alice@example.org", "victim@example.com", None),
		// A client wrote its own.
		ours(
			"alice@example.org",
			"victim@example.com",
			Some("campaign42:newsletter"),
		),
		// The form, for a domain that is not hosted here.
		ours(
			"alice@example.org",
			"victim@example.com",
			Some("epistle:transactional:example.net"),
		),
		// A class this server does not have.
		ours(
			"alice@example.org",
			"victim@example.com",
			Some("epistle:bulk:example.org"),
		),
		// More fields than the form has.
		ours(
			"alice@example.org",
			"victim@example.com",
			Some("epistle:transactional:example.org:x"),
		),
		// A sender that is not an account here.
		ours("nobody@example.org", "victim@example.com", Some(ID)),
		// A From of another domain than the Feedback-ID names.
		ours("alice@example.net", "victim@example.com", Some(ID)),
		// The complainant was not an addressee of the quoted message.
		ours("alice@example.org", "someone@example.com", Some(ID)),
		// No signature of ours: another domain's, a selector we do not have, none.
		ours("alice@example.org", "victim@example.com", Some(ID))
			.replace("d=example.org", "d=example.net"),
		ours("alice@example.org", "victim@example.com", Some(ID)).replace("s=s1", "s=other"),
		ours("alice@example.org", "victim@example.com", Some(ID))
			.replace("DKIM-Signature", "X-Signature"),
		// A Message-ID of somebody else's domain.
		ours("alice@example.org", "victim@example.com", Some(ID))
			.replace("<1@example.org>", "<1@elsewhere.example>"),
	] {
		let data = report(&complaint_fields("victim@example.com"), &quoted);
		let (outcome, dir, metrics) = run(&fbl(""), &verified(data));
		assert_eq!(outcome, Outcome::NotOurs, "{quoted}");
		assert_untouched(&dir, &metrics);
	}
}

#[test]
fn a_report_that_quotes_no_headers_is_not_ours() {
	let data = String::from_utf8(valid_report("victim@example.com"))
		.expect("utf8")
		.replace("message/rfc822", "text/plain");
	let (outcome, dir, metrics) = run(&fbl(""), &verified(data.into_bytes()));
	assert_eq!(outcome, Outcome::NotOurs);
	assert_untouched(&dir, &metrics);
}

#[test]
fn an_account_over_its_hourly_cap_suppresses_no_more() {
	let capped = fbl("fbl_max_per_hour = 2");
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Metrics::new();
	let outcomes: Vec<Outcome> = (0..4)
		.map(|n| {
			let message = verified(valid_report(&format!("victim{n}@example.com")));
			process(&capped, dir.path(), &directory(), &message, Some(&metrics))
		})
		.collect();
	assert!(matches!(outcomes[0], Outcome::Counted { .. }));
	assert!(matches!(outcomes[1], Outcome::Counted { .. }));
	assert_eq!(outcomes[2], Outcome::Limited);
	assert_eq!(outcomes[3], Outcome::Limited);
	let list = SuppressionList::open(dir.path()).expect("list");
	assert_eq!(list.entries_for("alice").len(), 2);
	assert_eq!(metrics.snapshot()["fbl_complaints"], 2);
}

#[test]
fn only_the_named_recipient_is_suppressed_never_another_addressee() {
	let quoted = original(
		"alice@example.org",
		"victim@example.com, bystander@example.com",
		Some("epistle:transactional:example.org"),
	);
	let data = report(&complaint_fields("victim@example.com"), &quoted);
	let (outcome, dir, _metrics) = run(&fbl(""), &verified(data));
	assert!(matches!(outcome, Outcome::Counted { .. }));
	let list = SuppressionList::open(dir.path()).expect("list");
	assert_eq!(
		list.list_for("alice"),
		vec!["victim@example.com".to_string()]
	);
}
