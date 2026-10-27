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

#[tokio::test]
async fn the_api_answers_a_padded_submission_with_422() {
	use axum::response::IntoResponse;
	let response = super::v1::sink_refusal(SinkError::TooManyHeaderFields).into_response();
	assert_eq!(response.status().as_u16(), 422);
	let body = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
	assert_eq!(json["error"]["code"], "too_many_header_fields", "{json}");
}

#[test]
fn smtp_refuses_a_padded_message_for_good() {
	let reply = SinkError::TooManyHeaderFields.smtp_reply();
	let text = format!("{reply:?}");
	assert!(text.contains("554") && text.contains("5.6.0"), "{text}");
}

#[test]
fn a_refusal_is_counted_and_said_once_an_hour() {
	use crate::cli::trace::capture::run_with_capture;
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
	let delivery = LocalDelivery::new(dir.path(), directory)
		.expect("delivery")
		.with_metrics(metrics.clone());
	let message = AcceptedMessage {
		reverse_path: "bob@elsewhere.example".to_string(),
		recipients: vec!["alice@example.org".to_string()],
		data: padded_draft(MAX_HEADER_FIELDS).into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let events = run_with_capture(|| {
		for _ in 0..4 {
			assert!(delivery.deliver_routed(&message, None).is_err());
		}
	});
	assert_eq!(metrics.snapshot()["rejected_header_fields"], 4);
	let said = events
		.iter()
		.filter(|e| {
			e.fields
				.get("message")
				.is_some_and(|m| m.contains("too many header fields"))
		})
		.count();
	// Another test may have said it this hour already: never more than one.
	assert!(said <= 1, "four refusals, {said} lines");
}

#[test]
fn a_message_with_bare_lf_is_all_header_here_and_refused_when_it_has_thousands_of_lines() {
	// Readers end the header block at different places for bare LF (IMAP and
	// POP3 at LF LF, others only at CRLF CRLF). The count takes the longest,
	// so a message with LF line ends is counted whole: a long one is refused
	// (the safe side), a short one is delivered.
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let delivery = LocalDelivery::new(dir.path(), directory).expect("delivery");
	let message = |lines: usize| {
		let mut data = b"From: bob@elsewhere.example\nSubject: hi\n\n".to_vec();
		for n in 0..lines {
			data.extend_from_slice(format!("line {n}\n").as_bytes());
		}
		AcceptedMessage {
			reverse_path: "bob@elsewhere.example".to_string(),
			recipients: vec!["alice@example.org".to_string()],
			data,
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: true,
			no_dsn: Vec::new(),
		}
	};
	delivery
		.deliver_routed(&message(100), None)
		.expect("a short message with LF is delivered");
	assert!(matches!(
		delivery.deliver_routed(&message(MAX_HEADER_FIELDS + 2_000), None),
		Err(SinkError::TooManyHeaderFields)
	));
}

/// A sink that refuses everything for having too many header fields.
struct Padded;

impl crate::smtp::sink::MessageSink for Padded {
	fn deliver(&self, _: AcceptedMessage) -> Result<(), SinkError> {
		Err(SinkError::TooManyHeaderFields)
	}
}

#[tokio::test]
async fn post_api_send_answers_a_padded_refusal_with_422() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app =
		router(super::tests::test_state(dir.path(), 0).with_outbound(std::sync::Arc::new(Padded)));
	let (status, body) = super::tests::request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(super::tests::TOKEN.as_str()),
		Some(serde_json::json!({
			"from": "alice@example.org", "to": ["bob@elsewhere.example"],
			"subject": "s", "text": "hello"
		})),
	)
	.await;
	assert_eq!(status.as_u16(), 422, "{body}");
	assert_eq!(body["error"]["code"], "too_many_header_fields", "{body}");
}
