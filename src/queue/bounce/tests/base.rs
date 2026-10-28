use super::*;
use std::time::{Duration, UNIX_EPOCH};

fn original() -> &'static [u8] {
	b"From: alice@example.org\r\nSubject: hi\r\n\r\nsecret body\r\n"
}

#[test]
fn builds_bounce_to_the_sender() {
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["bob@elsewhere.example".to_string()],
		"550 5.1.1 no such user",
		original(),
		UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		true,
	)
	.expect("bounce built");

	assert_eq!(bounce.reverse_path, "");
	assert_eq!(bounce.recipients, vec!["alice@example.org".to_string()]);
	let body = String::from_utf8(bounce.data).expect("ascii");
	assert!(body.contains("MAILER-DAEMON@mail.example.org"), "{body}");
	assert!(body.contains("bob@elsewhere.example"), "{body}");
	assert!(body.contains("550 5.1.1 no such user"), "{body}");
	assert!(body.contains("Subject: hi"), "{body}");
	// The original body must not leak into the bounce.
	assert!(!body.contains("secret body"), "{body}");
	assert!(body.contains("Auto-Submitted: auto-generated"), "{body}");
}

#[test]
fn produces_rfc3464_delivery_status() {
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["bob@elsewhere.example".to_string()],
		"550 5.1.1 no such user",
		original(),
		UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		true,
	)
	.expect("bounce built");
	let body = String::from_utf8(bounce.data).expect("ascii");

	assert!(
		body.contains("Content-Type: multipart/report; report-type=delivery-status"),
		"{body}"
	);
	assert!(
		body.contains("Content-Type: message/delivery-status"),
		"{body}"
	);
	assert!(
		body.contains("Reporting-MTA: dns; mail.example.org"),
		"{body}"
	);
	assert!(
		body.contains("Final-Recipient: rfc822; bob@elsewhere.example"),
		"{body}"
	);
	assert!(body.contains("Action: failed"), "{body}");
	// Enhanced status extracted from the reason.
	assert!(body.contains("Status: 5.1.1"), "{body}");
	assert!(
		body.contains("Diagnostic-Code: smtp; 550 5.1.1 no such user"),
		"{body}"
	);
	assert!(
		body.contains("Content-Type: message/rfc822-headers"),
		"{body}"
	);
	// The closing boundary terminates the report.
	assert!(body.trim_end().ends_with("--"), "{body}");
}

#[test]
fn defaults_status_when_reason_has_no_code() {
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["b@c.example".to_string()],
		"connection timed out",
		original(),
		UNIX_EPOCH,
		true,
	)
	.expect("bounce built");
	let body = String::from_utf8(bounce.data).expect("ascii");
	assert!(body.contains("Status: 5.0.0"), "{body}");
}

#[test]
fn reports_each_failed_recipient() {
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["b@c.example".to_string(), "d@e.example".to_string()],
		"550 5.2.1 mailbox disabled",
		original(),
		UNIX_EPOCH,
		true,
	)
	.expect("bounce built");
	let body = String::from_utf8(bounce.data).expect("ascii");
	assert_eq!(
		body.matches("Final-Recipient: rfc822;").count(),
		2,
		"{body}"
	);
}

#[test]
fn delay_warning_is_transient_and_keeps_retrying() {
	let warning = build_delay_warning(
		"mail.example.org",
		"alice@example.org",
		&[ReportRecipient::new(
			"bob@elsewhere.example",
			"451 4.4.1 connection timed out",
		)],
		original(),
		UNIX_EPOCH,
		true,
	)
	.expect("warning built");
	assert_eq!(warning.reverse_path, "");
	let body = String::from_utf8(warning.data).expect("ascii");
	assert!(body.contains("Action: delayed"), "{body}");
	assert!(body.contains("Status: 4.4.1"), "{body}");
	assert!(
		body.contains("Subject: Delivery Status Notification (Delay)"),
		"{body}"
	);
	assert!(body.contains("retried"), "{body}");
	// A delayed report must never be returned for a bounce.
	assert!(
		build_delay_warning(
			"h.example",
			"",
			&[ReportRecipient::new("x@y.example", "r")],
			original(),
			UNIX_EPOCH,
			true,
		)
		.is_none()
	);
}

#[test]
fn sanitizes_crlf_in_reason_to_prevent_header_injection() {
	// A hostile/compromised remote MTA returns a reply whose line contains a
	// CRLF and a forged header. It must not appear as a real header (or any
	// new line) in the DSN we generate.
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["bob@elsewhere.example".to_string()],
		"550 rejected\r\nBcc: attacker@evil.example\r\nX-Injected: yes",
		original(),
		UNIX_EPOCH,
		true,
	)
	.expect("bounce built");
	let body = String::from_utf8(bounce.data).expect("ascii");
	// The injected header must never appear at the start of a line.
	assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
	assert!(!body.contains("\r\nX-Injected: yes"), "{body}");
	// The control characters are flattened to spaces, so the reason text is
	// still present on a single line.
	assert!(
		body.contains("550 rejected  Bcc: attacker@evil.example  X-Injected: yes"),
		"{body}"
	);
}

#[test]
fn caps_reason_length() {
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["bob@elsewhere.example".to_string()],
		&"x".repeat(5_000),
		original(),
		UNIX_EPOCH,
		true,
	)
	.expect("bounce built");
	let body = String::from_utf8(bounce.data).expect("ascii");
	// The reason appears twice (header + text part); each is capped to 512.
	assert!(!body.contains(&"x".repeat(513)), "reason not capped");
}

#[test]
fn never_bounces_a_bounce() {
	assert!(
		build(
			"mail.example.org",
			"",
			&["x@example.org".to_string()],
			"reason",
			original(),
			UNIX_EPOCH,
			true,
		)
		.is_none()
	);
}

#[test]
fn caps_quoted_headers() {
	let mut huge = b"From: a@example.org\r\n".to_vec();
	huge.extend(std::iter::repeat_n(b'x', 100_000));
	let bounce = build(
		"mail.example.org",
		"alice@example.org",
		&["b@c.example".to_string()],
		"reason",
		&huge,
		UNIX_EPOCH,
		true,
	)
	.expect("bounce built");
	assert!(bounce.data.len() < 10_000);
}
