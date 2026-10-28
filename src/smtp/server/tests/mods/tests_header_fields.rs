//! A message with thousands of header fields would be read by a Sieve filter
//! only in part; the server refuses it at DATA, so the cut is never reached
//! by mail from outside.

use super::tests_data_rate::{Client, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::MAX_HEADER_FIELDS;

async fn send(fields: usize) -> (Vec<String>, usize, u64) {
	let sink = Arc::new(MemorySink::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_metrics(Arc::clone(&metrics)),
	);
	let mut client = Client::connect(&server);
	let mut session = b"EHLO client.example.org\r\nMAIL FROM:<a@example.net>\r\n\
		RCPT TO:<bob@example.org>\r\nDATA\r\n"
		.to_vec();
	for n in 0..fields {
		session.extend_from_slice(format!("x{n}: y\r\n").as_bytes());
	}
	session.extend_from_slice(b"Subject: s\r\n\r\nhello\r\n.\r\nQUIT\r\n");
	client.send(&session).await;
	let output = client.finish().await;
	let codes = reply_codes(&output).into_iter().map(String::from).collect();
	let counted = metrics.snapshot()["rejected_header_fields"];
	(codes, sink.messages().len(), counted)
}

#[tokio::test(start_paused = true)]
async fn a_message_one_field_over_the_limit_is_refused_at_data() {
	// The fields sent plus the Subject the helper adds.
	let (codes, delivered, counted) = send(crate::smtp::trace::MAX_HEADER_FIELDS).await;
	assert!(codes.iter().any(|c| c == "554"), "{codes:?}");
	assert_eq!(delivered, 0);
	assert_eq!(counted, 1, "the refusal is counted");
}

#[tokio::test(start_paused = true)]
async fn a_message_at_the_header_field_limit_is_accepted() {
	// The fields sent plus the Subject the helper adds.
	let (codes, delivered, counted) = send(crate::smtp::trace::MAX_HEADER_FIELDS - 1).await;
	assert!(!codes.iter().any(|c| c == "554"), "{codes:?}");
	assert_eq!(delivered, 1);
	assert_eq!(counted, 0);
}

#[test]
fn folded_lines_are_not_header_fields() {
	// Three fields with thousands of folded lines each are three fields.
	let mut raw = Vec::new();
	for name in ["A", "B", "C"] {
		raw.extend_from_slice(format!("{name}: start\r\n").as_bytes());
		for _ in 0..(MAX_HEADER_FIELDS + 10) {
			raw.extend_from_slice(b" more\r\n");
		}
	}
	raw.extend_from_slice(b"\r\nbody\r\n");
	assert_eq!(crate::util::header_block::field_count(&raw), 3);
	assert!(crate::smtp::trace::refuse_padded_headers(&raw, None).is_ok());
}
