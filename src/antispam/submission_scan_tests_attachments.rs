//! The attachment policy on what local accounts submit.

use super::*;
use crate::antispam::attachments::corpus;
use crate::config::{AttachmentMode, Attachments};
use crate::smtp::sink::MemorySink;

fn policy(mode: AttachmentMode) -> Arc<Policy> {
	let section = Attachments {
		mode,
		..Attachments::default()
	};
	Arc::new(Policy::from_config(&section, 1 << 20).expect("mode is not off"))
}

fn disguised() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data: corpus::message(&[corpus::attachment(
			"Content-Type: application/pdf; name=\"factura.pdf.exe\"",
			&corpus::pe(),
		)]),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

fn submit_with(
	scan_authenticated: bool,
	mode: AttachmentMode,
) -> (Result<(), SinkError>, Arc<MemorySink>) {
	let inner = Arc::new(MemorySink::new());
	let sink = ScanningSink::wrap_with_attachments(
		scan_authenticated,
		inner.clone(),
		None,
		Some(policy(mode)),
		None,
		None,
	)
	.expect("sink");
	let result = sink.submit(
		disguised(),
		uuid::Uuid::now_v7(),
		"alice",
		&crate::smtp::sink::Submission::default(),
	);
	(result, inner)
}

#[test]
fn quarantine_or_reject_refuses_the_submission_with_the_policy_reply() {
	for mode in [AttachmentMode::Quarantine, AttachmentMode::Reject] {
		let (result, inner) = submit_with(true, mode);
		let error = result.expect_err("refused");
		assert_eq!(
			error.smtp_reply().to_string(),
			"550 5.7.1 attachment type not accepted\r\n",
			"{mode:?}"
		);
		assert!(
			matches!(&error, SinkError::AttachmentRefused(codes) if codes.contains("double-extension")),
			"{error}"
		);
		assert!(inner.messages().is_empty(), "nothing was routed");
	}
}

#[test]
fn flag_lets_the_submission_through_untouched() {
	let (result, inner) = submit_with(true, AttachmentMode::Flag);
	assert!(result.is_ok());
	let routed = inner.messages();
	assert_eq!(routed.len(), 1);
	assert_eq!(
		routed[0].data,
		disguised().data,
		"submitted mail is not rewritten"
	);
}

#[test]
fn with_scan_authenticated_off_the_policy_does_not_apply() {
	let (result, inner) = submit_with(false, AttachmentMode::Reject);
	assert!(result.is_ok());
	assert_eq!(inner.messages().len(), 1);
}
