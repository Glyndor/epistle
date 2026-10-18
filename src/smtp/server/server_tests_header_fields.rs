//! A message with thousands of header fields would be read by a Sieve filter
//! only in part; the server refuses it at DATA, so the cut is never reached
//! by mail from outside.

use super::tests_data_rate::{Client, reply_codes, test_directory};
use super::*;
use crate::smtp::sink::MemorySink;

async fn send(fields: usize) -> (Vec<String>, usize) {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(
		Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory()),
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
	(codes, sink.messages().len())
}

#[tokio::test(start_paused = true)]
async fn a_message_with_thousands_of_header_fields_is_refused_at_data() {
	let (codes, delivered) = send(crate::smtp::trace::MAX_HEADER_FIELDS + 1).await;
	assert!(codes.iter().any(|c| c == "554"), "{codes:?}");
	assert_eq!(delivered, 0);
}

#[tokio::test(start_paused = true)]
async fn a_message_at_the_header_field_limit_is_accepted() {
	let (codes, delivered) = send(crate::smtp::trace::MAX_HEADER_FIELDS - 1).await;
	assert!(!codes.iter().any(|c| c == "554"), "{codes:?}");
	assert_eq!(delivered, 1);
}
