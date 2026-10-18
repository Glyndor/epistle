//! Padding a message with header fields must not hide the ones a filter
//! looks at, whichever way the message gets to the recipient: JMAP
//! `EmailSubmission/set` and the local delivery itself refuse it like SMTP.

use super::router;
use super::send_tests_outbound::routed_state;
use super::send_tests_virus::jmap_submit;
use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::SinkError;
use crate::smtp::trace::MAX_HEADER_FIELDS;
use crate::storage::LocalDelivery;

/// A draft of alice to herself with `fields` filler header fields.
fn padded_draft(fields: usize) -> String {
	let mut raw = String::from("From: alice@example.org\r\nTo: alice@example.org\r\n");
	for n in 0..fields {
		raw.push_str(&format!("x{n}: y\r\n"));
	}
	raw.push_str("Subject: cheap viagra\r\n\r\nbody\r\n");
	raw
}

#[tokio::test]
async fn a_jmap_submission_with_thousands_of_header_fields_is_forbidden_to_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let response = jmap_submit(&app, dir.path(), &padded_draft(MAX_HEADER_FIELDS)).await;
	let refusal = &response["notCreated"]["s"];
	assert_eq!(refusal["type"], "forbiddenToSend", "{response}");
	let response = jmap_submit(&app, dir.path(), &padded_draft(100)).await;
	assert!(response["created"]["s"].is_object(), "{response}");
}

#[test]
fn the_local_delivery_refuses_a_message_with_too_many_header_fields() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let delivery = LocalDelivery::new(dir.path(), directory).expect("delivery");
	let message = |fields: usize| AcceptedMessage {
		reverse_path: "bob@elsewhere.example".to_string(),
		recipients: vec!["alice@example.org".to_string()],
		data: padded_draft(fields).into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	assert!(matches!(
		delivery.deliver_routed(&message(MAX_HEADER_FIELDS), None),
		Err(SinkError::TooManyHeaderFields)
	));
	// From, To and Subject count too: one field over the limit is refused,
	// and one at the limit is delivered.
	assert!(matches!(
		delivery.deliver_routed(&message(MAX_HEADER_FIELDS - 2), None),
		Err(SinkError::TooManyHeaderFields)
	));
	delivery
		.deliver_routed(&message(MAX_HEADER_FIELDS - 3), None)
		.expect("a message at the limit is delivered");
}
