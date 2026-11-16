//! A local failure's status and fixed sentence in the report.

use super::*;
use crate::queue::local_failure::LocalFailure;
use std::time::UNIX_EPOCH;

fn reason(failure: LocalFailure) -> String {
	match failure.transient("mx.example.net", "detail") {
		crate::queue::client::DeliveryError::Transient(reason) => reason,
		crate::queue::client::DeliveryError::Permanent(reason) => reason,
	}
}

fn fields(kind: Kind, recipient: &ReportRecipient) -> String {
	let fields = recipient_fields(kind, recipient, &recipient.reason);
	assert!(fields.ends_with("\r\n\r\n"));
	fields
}

#[test]
fn a_given_up_message_carries_the_permanent_status_and_the_sentence() {
	for (failure, status) in [
		(LocalFailure::TlsRequired, "5.7.10"),
		(LocalFailure::TlsaMismatch, "5.7.5"),
		(LocalFailure::TlsaLookup, "5.7.5"),
		(LocalFailure::Handshake, "5.7.5"),
		(LocalFailure::MtaStsNoServer, "5.7.5"),
		(LocalFailure::Dnssec, "5.7.5"),
		(LocalFailure::Unreachable, "5.4.1"),
		(LocalFailure::MxLookup, "5.4.3"),
	] {
		let reason = reason(failure);
		let recipient = ReportRecipient::new("bob@elsewhere.example", &reason);
		let fields = fields(Kind::Failed, &recipient);
		let sentence = reason.split_once(' ').expect("status and sentence").1;
		assert!(
			fields.contains(&format!("Status: {status}\r\n")),
			"{fields}"
		);
		assert!(
			fields.contains(&format!("Diagnostic-Code: X-epistle; {sentence}\r\n")),
			"{fields}"
		);
		assert!(!fields.contains("smtp;"), "{fields}");
	}
}

#[test]
fn a_delay_warning_carries_the_temporary_status() {
	let reason = reason(LocalFailure::TlsRequired);
	let recipient = ReportRecipient::new("bob@elsewhere.example", &reason);
	let fields = fields(Kind::Delayed, &recipient);
	assert!(fields.contains("Status: 4.7.10\r\n"), "{fields}");
	assert!(fields.contains("Action: delayed\r\n"), "{fields}");
}

#[test]
fn an_expired_message_keeps_the_status_of_its_last_local_failure() {
	let reason = reason(LocalFailure::Handshake);
	let mut recipient = ReportRecipient::new("bob@elsewhere.example", &reason);
	recipient.expired = true;
	let fields = fields(Kind::Failed, &recipient);
	assert!(fields.contains("Status: 5.7.5\r\n"), "{fields}");
}

#[test]
fn a_local_reason_without_a_status_keeps_the_old_report() {
	let recipient = ReportRecipient::new("bob@elsewhere.example", "connection timed out");
	let fields = fields(Kind::Failed, &recipient);
	assert!(fields.contains("Status: 5.0.0\r\n"), "{fields}");
	assert!(!fields.contains("Diagnostic-Code"), "{fields}");
}

#[test]
fn the_sentence_cannot_open_a_header_of_its_own() {
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["bob@elsewhere.example".to_string()],
		"4.7.5 the TLS handshake with mx failed\r\nBcc: evil@example.net",
		b"From: alice@example.org\r\n\r\nx\r\n",
		UNIX_EPOCH,
		true,
		true,
	)
	.expect("bounce built");
	let body = String::from_utf8(bounce.data).expect("ascii");
	assert!(!body.contains("\r\nBcc:"), "{body}");
}
