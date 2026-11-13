//! Identification tests: list headers, unsubscribe links and bulk detection.

use super::*;
use crate::cli::trace::capture::run_with_capture;

#[test]
fn a_list_sender_gets_the_list_headers_and_a_plain_one_does_not() {
	let mut list = submitted("team@example.org", &["bob@elsewhere.example"], "");
	apply_to(&mut list, MailClass::Personal, &policy());
	assert_eq!(
		values(&list, "list-id"),
		vec!["<team.example.org>".to_string()]
	);
	assert_eq!(
		values(&list, "list-post"),
		vec!["<mailto:team@example.org>".to_string()]
	);

	let mut plain = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	apply_to(&mut plain, MailClass::Personal, &policy());
	assert!(values(&plain, "list-id").is_empty());
}

#[test]
fn no_list_headers_are_written_when_the_switch_is_off() {
	let mut message = submitted("team@example.org", &["bob@elsewhere.example"], "");
	apply_to(
		&mut message,
		MailClass::Personal,
		&Policy {
			list_id: false,
			..policy()
		},
	);
	assert!(values(&message, "list-id").is_empty());
}

#[test]
fn bulk_transactional_mail_gets_a_mailto_unsubscribe() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"",
	);
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<mailto:alice@example.org?subject=unsubscribe>".to_string()]
	);
}

#[test]
fn one_recipient_personal_mail_and_marketing_mail_get_no_mailto() {
	for (class, recipients) in [
		(MailClass::Transactional, vec!["bob@elsewhere.example"]),
		(
			MailClass::Personal,
			vec!["bob@elsewhere.example", "carol@elsewhere.example"],
		),
		(
			MailClass::Marketing,
			vec!["bob@elsewhere.example", "carol@elsewhere.example"],
		),
	] {
		let mut message = submitted("alice@example.org", &recipients, "");
		apply_to(&mut message, class, &policy());
		assert!(
			values(&message, "list-unsubscribe").is_empty(),
			"{class} to {recipients:?} got one"
		);
	}
}

#[test]
fn the_bulk_threshold_is_the_configured_recipient_count() {
	let recipients = ["bob@elsewhere.example", "carol@elsewhere.example"];
	let mut message = submitted("alice@example.org", &recipients, "");
	apply_to(
		&mut message,
		MailClass::Transactional,
		&Policy {
			bulk_recipients: 2,
			..policy()
		},
	);
	assert!(values(&message, "list-unsubscribe").is_empty());

	let mut message = submitted("alice@example.org", &recipients, "");
	apply_to(
		&mut message,
		MailClass::Transactional,
		&Policy {
			bulk_unsubscribe: false,
			..policy()
		},
	);
	assert!(values(&message, "list-unsubscribe").is_empty());
}

#[test]
fn an_unsubscribe_the_client_sent_is_not_replaced() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"List-Unsubscribe: <https://example.org/u>\r\n",
	);
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<https://example.org/u>".to_string()]
	);
}

#[test]
fn a_list_sender_that_also_counts_as_bulk_gets_one_unsubscribe() {
	let mut message = submitted(
		"team@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"",
	);
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<mailto:team@example.org?subject=unsubscribe>".to_string()],
		"two unsubcribes, where a receiver may follow neither"
	);
	assert_eq!(
		values(&message, "list-id"),
		vec!["<team.example.org>".to_string()]
	);
}

#[test]
fn a_list_sender_keeps_the_one_click_unsubscribe_it_chose() {
	let mut message = submitted(
		"team@example.org",
		&["bob@elsewhere.example"],
		"List-Unsubscribe: <https://example.org/u>\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	apply_to(&mut message, MailClass::Marketing, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<https://example.org/u>".to_string()],
		"the list block replaced an https the client published"
	);
	assert_eq!(
		values(&message, "list-unsubscribe-post"),
		vec!["List-Unsubscribe=One-Click".to_string()],
		"a one-click post left naming a mailto that is not there"
	);
	assert_eq!(
		values(&message, "list-id"),
		vec!["<team.example.org>".to_string()],
		"the list block is not written at all: {:?}",
		values(&message, "list-id")
	);
}

#[test]
fn the_mailto_unsubscribe_is_percent_encoded() {
	let mut message = submitted(
		"a?b&c%d@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"",
	);
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<mailto:a%3Fb%26c%25d@example.org?subject=unsubscribe>".to_string()],
		"RFC 6068: `?`, `&` and `%` in an address cannot read as a query"
	);

	// A slash is atext, so it is one more character a client may put in its
	// own local part, and one more delimiter a URI would read it as.
	let mut slashed = submitted(
		"a/b@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"",
	);
	apply_to(&mut slashed, MailClass::Transactional, &policy());
	assert_eq!(
		values(&slashed, "list-unsubscribe"),
		vec!["<mailto:a%2Fb@example.org?subject=unsubscribe>".to_string()],
		"RFC 6068: a slash in an address is a path delimiter unless it is encoded"
	);
}

#[test]
fn a_sender_outside_ascii_still_gets_an_encoded_unsubscribe() {
	let mut message = submitted(
		"josé@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"",
	);
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<mailto:jos%C3%A9@example.org?subject=unsubscribe>".to_string()]
	);
}

#[test]
fn an_empty_reverse_path_writes_neither_feedback_id_nor_unsubscribe() {
	let mut message = submitted(
		"",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"",
	);
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert!(
		values(&message, "feedback-id").is_empty(),
		"a Feedback-ID with no domain names nothing: {:?}",
		values(&message, "feedback-id")
	);
	assert!(
		values(&message, "list-unsubscribe").is_empty(),
		"a mailto with no address to write to: {:?}",
		values(&message, "list-unsubscribe")
	);
}

#[test]
fn a_domain_outside_ascii_leaves_the_feedback_id_out_and_says_why() {
	let mut message = submitted("alice@exämple.org", &["bob@elsewhere.example"], "");
	let events = run_with_capture(|| apply_to(&mut message, MailClass::Transactional, &policy()));
	assert!(
		values(&message, "feedback-id").is_empty(),
		"RFC 2919 has no room for a non-ASCII domain: {:?}",
		values(&message, "feedback-id")
	);
	let said = events
		.iter()
		.filter(|event| {
			event
				.fields
				.get("name")
				.is_some_and(|name| name.contains("Feedback-ID"))
		})
		.count();
	assert_eq!(said, 1, "the header left out in silence: {events:?}");
}

#[test]
fn twenty_recipients_is_not_bulk_by_default() {
	assert_eq!(
		Policy::default().bulk_recipients,
		20,
		"the shipped threshold moved"
	);
	let twenty: Vec<String> = (0..20)
		.map(|n| format!("bob{n}@elsewhere.example"))
		.collect();
	let recipients: Vec<&str> = twenty.iter().map(String::as_str).collect();
	let mut message = submitted("alice@example.org", &recipients, "");
	apply_to(&mut message, MailClass::Transactional, &Policy::default());
	assert!(
		values(&message, "list-unsubscribe").is_empty(),
		"a notice to twenty people is not bulk mail: {:?}",
		values(&message, "list-unsubscribe")
	);

	let over = [recipients.as_slice(), &["bob@elsewhere.example"]].concat();
	let mut message = submitted("alice@example.org", &over, "");
	apply_to(&mut message, MailClass::Transactional, &Policy::default());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<mailto:alice@example.org?subject=unsubscribe>".to_string()],
		"one recipient over the threshold is not bulk either"
	);
}
