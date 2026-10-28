
use super::*;

#[test]
fn memory_sink_collects_messages() {
	let sink = MemorySink::new();
	let message = AcceptedMessage {
		reverse_path: "a@example.org".into(),
		recipients: vec!["b@example.org".into()],
		data: b"hello\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	};
	sink.deliver(message.clone()).expect("delivery succeeds");
	assert_eq!(sink.messages(), vec![message]);
}

#[test]
fn a_sink_that_keeps_no_evidence_refuses_transactional_mail() {
	let sink = MemorySink::new();
	let message = AcceptedMessage {
		reverse_path: "a@example.org".into(),
		recipients: vec!["b@example.org".into()],
		data: b"hello\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	};
	let refused = sink.submit(
		message.clone(),
		uuid::Uuid::now_v7(),
		"a",
		&Submission::of_class(crate::evidence::MailClass::Transactional),
	);
	assert!(matches!(refused, Err(SinkError::EvidenceUnavailable(_))));
	assert!(sink.messages().is_empty(), "the message was taken anyway");
	sink.submit(message, uuid::Uuid::now_v7(), "a", &Submission::default())
		.expect("personal mail is taken");
	assert_eq!(sink.messages().len(), 1);
}
