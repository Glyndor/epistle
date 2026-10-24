//! What a client may write in the fields the server owns: one copy of each,
//! the namespace reserved by name, and no `List-Unsubscribe-Post` left
//! naming a `mailto:` the server wrote over its own.

use super::*;

#[test]
fn a_repeated_identification_field_from_the_client_keeps_one_copy() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"Feedback-ID: campaign:1234:example.org\r\n\
		 Feedback-ID: campaign:5678:example.org\r\n\
		 List-Unsubscribe: <https://example.org/u/1>\r\n\
		 List-Unsubscribe: <https://example.org/u/2>\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
		 Organization: Their Own Name\r\n\
		 Organization: Their Other Name\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	for (field, kept) in [
		("feedback-id", "campaign:1234:example.org"),
		("list-unsubscribe", "<https://example.org/u/1>"),
		("list-unsubscribe-post", "List-Unsubscribe=One-Click"),
		("organization", "Their Own Name"),
	] {
		assert_eq!(
			values(&message, field),
			vec![kept.to_string()],
			"two {field} fields, where a receiver may follow neither"
		);
	}
}

#[test]
fn the_list_fields_the_server_writes_replace_every_copy_the_client_sent() {
	let mut message = submitted(
		"team@example.org",
		&["bob@elsewhere.example"],
		"List-Id: <someone-elses.example.org>\r\n\
		 List-Id: <another.example.org>\r\n\
		 List-Post: <mailto:someone@example.org>\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	assert_eq!(
		values(&message, "list-id"),
		vec!["<team.example.org>".to_string()],
		"the list claims a name that is not it: {:?}",
		values(&message, "list-id")
	);
	assert_eq!(
		values(&message, "list-post"),
		vec!["<mailto:team@example.org>".to_string()],
		"the list posts to an address that is not it: {:?}",
		values(&message, "list-post")
	);
}

#[test]
fn a_one_click_post_the_client_left_alone_does_not_survive_the_mailto() {
	// The list block writes the mailto, so nothing in the message posts to
	// an https the client published in some other transaction.
	let mut list = submitted(
		"team@example.org",
		&["bob@elsewhere.example"],
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	apply_to(&mut list, MailClass::Personal, &policy());
	assert_eq!(
		values(&list, "list-unsubscribe"),
		vec!["<mailto:team@example.org?subject=unsubscribe>".to_string()]
	);
	assert!(
		values(&list, "list-unsubscribe-post").is_empty(),
		"a one-click post naming a mailto that is not there: {:?}",
		values(&list, "list-unsubscribe-post")
	);

	// The same when the bulk mailto is what the server wrote.
	let mut bulk = submitted(
		"alice@example.org",
		&["bob@elsewhere.example", "carol@elsewhere.example"],
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	apply_to(&mut bulk, MailClass::Transactional, &policy());
	assert_eq!(
		values(&bulk, "list-unsubscribe"),
		vec!["<mailto:alice@example.org?subject=unsubscribe>".to_string()]
	);
	assert!(
		values(&bulk, "list-unsubscribe-post").is_empty(),
		"a one-click post naming a mailto that is not there: {:?}",
		values(&bulk, "list-unsubscribe-post")
	);
}

#[test]
fn a_one_click_post_whose_unsubscribe_stays_is_kept() {
	// The client's own https unsubscribe survives, so the post that names it
	// is still the answer to it (RFC 8058).
	let mut message = submitted(
		"team@example.org",
		&["bob@elsewhere.example"],
		"List-Unsubscribe: <https://example.org/u>\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<https://example.org/u>".to_string()]
	);
	assert_eq!(
		values(&message, "list-unsubscribe-post"),
		vec!["List-Unsubscribe=One-Click".to_string()],
		"the post lost the https it names: {:?}",
		values(&message, "list-unsubscribe-post")
	);
}

#[test]
fn the_list_block_names_the_canonical_alias_address() {
	let mut message = submitted("Team@EXAMPLE.org", &["bob@elsewhere.example"], "");
	apply_to(&mut message, MailClass::Personal, &policy());
	assert_eq!(
		values(&message, "list-post"),
		vec!["<mailto:team@example.org>".to_string()],
		"the alias spelled as the client wrote it, which a receiver has to \
		 answer case-insensitively: {:?}",
		values(&message, "list-post")
	);
	assert_eq!(
		values(&message, "list-unsubscribe"),
		vec!["<mailto:team@example.org?subject=unsubscribe>".to_string()],
		"the unsubscribe of a mailbox nobody owns under that spelling: {:?}",
		values(&message, "list-unsubscribe")
	);
}

#[test]
fn a_field_that_only_starts_like_our_namespace_is_the_clients() {
	let mut message = submitted(
		"alice@example.org",
		&["bob@elsewhere.example"],
		"X-Epistlefoo: theirs\r\n\
		 X-Epistle2: theirs\r\n\
		 X-Epistle: 9\r\n\
		 X-Epistle-Future: theirs\r\n",
	);
	apply_to(&mut message, MailClass::Personal, &policy());
	assert_eq!(
		values(&message, "x-epistlefoo"),
		vec!["theirs".to_string()],
		"a field that merely starts like ours was dropped: {:?}",
		values(&message, "x-epistlefoo")
	);
	assert_eq!(
		values(&message, "x-epistle2"),
		vec!["theirs".to_string()],
		"a field that merely starts like ours was dropped: {:?}",
		values(&message, "x-epistle2")
	);
	assert!(
		values(&message, "x-epistle").is_empty(),
		"the client's own marker survived: {:?}",
		values(&message, "x-epistle")
	);
	assert!(
		values(&message, "x-epistle-future").is_empty(),
		"the namespace is not reserved: {:?}",
		values(&message, "x-epistle-future")
	);
}
