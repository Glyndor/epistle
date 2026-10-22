//! What each identification header is written for, and when it stays out.

use super::*;
use crate::cli::tracing_capture::run_with_capture;
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::{AliasSpec, Directory};
use crate::smtp::trace::header_values;

fn submitted(sender: &str, recipients: &[&str], headers: &str) -> AcceptedMessage {
	let mut raw = format!("From: Sender <{sender}>\r\nSubject: hello\r\n{headers}\r\nbody\r\n");
	raw.push_str("");
	AcceptedMessage {
		reverse_path: sender.to_string(),
		recipients: recipients.iter().map(|r| (*r).to_string()).collect(),
		data: raw.into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::default().with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: false,
			list_id: Some("team.example.org".to_string()),
		},
	)]))
}

fn policy() -> Policy {
	// The bulk threshold of one recipient, so a two-recipient submission
	// counts as bulk in the tests below. The default threshold is
	// `DEFAULT_BULK_RECIPIENTS`, and its own test uses it as it ships.
	Policy {
		bulk_recipients: 1,
		..Policy::default()
	}
}

fn apply_to(message: &mut AcceptedMessage, class: MailClass, policy: &Policy) {
	let directory = directory();
	apply(message, class, policy, Some(&directory.current()));
}

fn values(message: &AcceptedMessage, name: &str) -> Vec<String> {
	header_values(&message.data, name)
}

#[test]
fn a_default_feedback_id_names_the_class_and_the_domain() {
	let mut message = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	apply_to(&mut message, MailClass::Transactional, &policy());
	assert_eq!(
		values(&message, "feedback-id"),
		vec!["epistle:transactional:example.org".to_string()]
	);
}

#[test]
fn a_feedback_id_the_client_sent_is_kept() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"Feedback-ID: campaign:1234:example.org\r\n",
	);
	apply_to(&mut message, MailClass::Marketing, &policy());
	assert_eq!(
		values(&message, "feedback-id"),
		vec!["campaign:1234:example.org".to_string()]
	);
}

#[test]
fn no_feedback_id_is_written_when_the_switch_is_off() {
	let mut message = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	apply_to(
		&mut message,
		MailClass::Personal,
		&Policy {
			feedback_id: false,
			..policy()
		},
	);
	assert!(values(&message, "feedback-id").is_empty());
}

#[test]
fn the_vendor_marker_is_off_by_default_and_carries_no_version() {
	let mut message = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	apply_to(&mut message, MailClass::Personal, &policy());
	assert!(values(&message, "x-epistle").is_empty());

	let mut message = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	apply_to(
		&mut message,
		MailClass::Personal,
		&Policy {
			x_epistle: true,
			..policy()
		},
	);
	assert_eq!(
		values(&message, "x-epistle"),
		vec![X_EPISTLE_VALUE.to_string()]
	);
}

#[test]
fn the_organization_of_the_sending_domain_is_written() {
	let mut with = policy();
	with.domain_organization
		.insert("example.org".to_string(), "Example Org".to_string());
	let mut message = submitted("alice@example.org", &["bob@elsewhere.example"], "");
	apply_to(&mut message, MailClass::Personal, &with);
	assert_eq!(
		values(&message, "organization"),
		vec!["Example Org".to_string()]
	);

	let mut message = submitted("alice@elsewhere.example", &["bob@elsewhere.example"], "");
	apply_to(&mut message, MailClass::Personal, &with);
	assert!(values(&message, "organization").is_empty());
}

#[test]
fn the_configured_organization_replaces_the_one_the_client_invented() {
	let mut with = policy();
	with.domain_organization
		.insert("example.org".to_string(), "Example Org".to_string());
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"Organization: Not Us\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &with);
	assert_eq!(
		values(&message, "organization"),
		vec!["Example Org".to_string()]
	);

	// With no value configured for the domain the server has no opinion,
	// so the client's own claim stays.
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"Organization: Their Own Name\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	assert_eq!(
		values(&message, "organization"),
		vec!["Their Own Name".to_string()]
	);
}

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

#[test]
fn a_client_cannot_speak_for_this_server() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"X-Epistle: 9\r\n\
		 X-Epistle-Attachment-Warning: attachment-policy\r\n\
		 X-Epistle-Future: anything\r\n\
		 Authentication-Results: forged.example; spf=pass\r\n",
	);
	apply_to(
		&mut message,
		MailClass::Personal,
		&Policy {
			x_epistle: true,
			..policy()
		},
	);
	assert_eq!(
		values(&message, "x-epistle"),
		vec![X_EPISTLE_VALUE.to_string()],
		"the client's own marker survived: {:?}",
		values(&message, "x-epistle")
	);
	assert!(
		values(&message, "x-epistle-future").is_empty(),
		"the namespace is not reserved: {:?}",
		values(&message, "x-epistle-future")
	);
	assert!(values(&message, "x-epistle-attachment-warning").is_empty());
	assert!(
		values(&message, "authentication-results").is_empty(),
		"a client forged our check results: {:?}",
		values(&message, "authentication-results")
	);
}

#[test]
fn a_client_cannot_write_our_namespace_even_when_the_marker_is_off() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"X-Epistle: 9\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	assert!(
		values(&message, "x-epistle").is_empty(),
		"{:?}",
		values(&message, "x-epistle")
	);
}

#[path = "identification_client_tests.rs"]
mod client;

#[test]
fn every_field_lands_above_the_headers_the_client_wrote() {
	let mut message = submitted("team@example.org", &["bob@elsewhere.example"], "");
	apply_to(&mut message, MailClass::Personal, &policy());
	let text = String::from_utf8_lossy(&message.data);
	let list = text.find("List-Id:").expect("the list id");
	let subject = text.find("Subject:").expect("the client subject");
	let body = text.find("body").expect("the body");
	assert!(list < subject && subject < body, "{text}");
	assert_eq!(text.matches("\r\n\r\n").count(), 1, "{text}");
}
