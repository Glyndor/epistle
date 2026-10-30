use super::*;
use std::time::{Duration, UNIX_EPOCH};

const REPORTED: &[u8] = b"From: spammer@bad.example\r\nSubject: buy now\r\n\r\nspam body\r\n";

fn report() -> Report<'static> {
	Report {
		report_to: "abuse@isp.example",
		feedback_type: FeedbackType::Abuse,
		original_mail_from: "spammer@bad.example",
		source_ip: Some("192.0.2.5"),
		reported_message: REPORTED,
	}
}

#[test]
fn builds_feedback_report() {
	let msg = build(
		"mail.example.org",
		&report(),
		UNIX_EPOCH + Duration::from_secs(1_780_662_896),
	);
	assert_eq!(msg.reverse_path, "");
	assert_eq!(msg.recipients, vec!["abuse@isp.example".to_string()]);
	let body = String::from_utf8(msg.data).expect("ascii");

	assert!(
		body.contains("Content-Type: multipart/report; report-type=feedback-report"),
		"{body}"
	);
	assert!(
		body.contains("Content-Type: message/feedback-report"),
		"{body}"
	);
	assert!(body.contains("Feedback-Type: abuse"), "{body}");
	assert!(body.contains("Version: 1"), "{body}");
	assert!(
		body.contains("Original-Mail-From: spammer@bad.example"),
		"{body}"
	);
	assert!(body.contains("Reported-Domain: bad.example"), "{body}");
	assert!(body.contains("Source-IP: 192.0.2.5"), "{body}");
	// The reported message is embedded.
	assert!(body.contains("Subject: buy now"), "{body}");
	assert!(body.trim_end().ends_with("--"), "{body}");
}

#[test]
fn omits_source_ip_when_unknown() {
	let mut report = report();
	report.source_ip = None;
	let body =
		String::from_utf8(build("mail.example.org", &report, UNIX_EPOCH).data).expect("ascii");
	assert!(!body.contains("Source-IP:"), "{body}");
}

#[test]
fn caps_embedded_message() {
	let mut huge = b"From: a@bad.example\r\n\r\n".to_vec();
	huge.extend(std::iter::repeat_n(b'x', 200_000));
	let mut report = report();
	report.reported_message = &huge;
	let msg = build("mail.example.org", &report, UNIX_EPOCH);
	assert!(msg.data.len() < 60_000);
}

#[test]
fn other_feedback_type_renders() {
	let mut report = report();
	report.feedback_type = FeedbackType::Other;
	let body =
		String::from_utf8(build("mail.example.org", &report, UNIX_EPOCH).data).expect("ascii");
	assert!(body.contains("Feedback-Type: other"), "{body}");
}

#[test]
fn parses_what_it_builds() {
	let built = build("mail.example.org", &report(), UNIX_EPOCH);
	let parsed = parse(&built.data).expect("our own report parses");
	assert_eq!(parsed.feedback_type, "abuse");
	assert_eq!(
		parsed.original_mail_from.as_deref(),
		Some("spammer@bad.example")
	);
	assert_eq!(parsed.source_ip.as_deref(), Some("192.0.2.5"));
	assert_eq!(parsed.reported_domain.as_deref(), Some("bad.example"));
}

#[test]
fn parses_external_report_with_lf_only() {
	let raw = b"Content-Type: multipart/report; report-type=feedback-report;\n\
\tboundary=\"b\"\n\
\n\
--b\n\
Content-Type: message/feedback-report\n\
\n\
Feedback-Type: fraud\n\
Original-Mail-From: phish@evil.example\n\
\n\
--b--\n";
	let parsed = parse(raw).expect("lf-only report parses");
	assert_eq!(parsed.feedback_type, "fraud");
	assert_eq!(
		parsed.original_mail_from.as_deref(),
		Some("phish@evil.example")
	);
	assert_eq!(parsed.source_ip, None);
}

#[test]
fn rejects_non_report_message() {
	let plain = b"From: a@example\r\nSubject: hi\r\n\r\nnot a report\r\n";
	assert_eq!(parse(plain), None);
}

#[test]
fn rejects_empty_input() {
	assert_eq!(parse(b""), None);
}

#[test]
fn rejects_report_without_feedback_type() {
	// Declares the report type but the machine part lacks Feedback-Type.
	let raw = b"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Original-Mail-From: spammer@bad.example\r\n\
\r\n\
--b--\r\n";
	assert_eq!(parse(raw), None);
}

#[test]
fn rejects_report_type_without_machine_part() {
	// Has the top-level marker but no message/feedback-report part.
	let raw = b"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
human only\r\n\
--b--\r\n";
	assert_eq!(parse(raw), None);
}

/// Inbound ARF complaints are unauthenticated. A CRLF in
/// `Original-Mail-From:` would, if interpolated raw into our reply,
/// terminate the line and start a new header. The build must sanitise:
/// the sanitiser collapses CRLF to a space, so the result is a single
/// header line with the `Bcc:` content as opaque text, not as a new
/// header.
#[test]
fn build_sanitises_crlf_in_original_mail_from() {
	let mut r = report();
	// A real-looking envelope sender plus a CRLF that, if echoed raw,
	// would start a forged `Bcc:` header.
	r.original_mail_from = "spammer@bad.example\r\nBcc: attacker@evil.example";
	let body = String::from_utf8(
		build(
			"mail.example.org",
			&r,
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		)
		.data,
	)
	.expect("ascii");
	// Scan the whole report: any line that starts with `Bcc:` is a
	// header-injection success.
	for line in body.lines() {
		assert!(
			!line.to_ascii_lowercase().starts_with("bcc:"),
			"forged Bcc: must not appear as its own header: {line:?}\n--- full body ---\n{body}"
		);
	}
}

/// A CRLF in `Source-IP:` would split the line. The build must sanitise:
/// the value lands on a single line, no forged header appears after it.
#[test]
fn build_sanitises_crlf_in_source_ip() {
	let mut r = report();
	r.source_ip = Some("192.0.2.5\r\nBcc: attacker@evil.example");
	let body = String::from_utf8(
		build(
			"mail.example.org",
			&r,
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		)
		.data,
	)
	.expect("ascii");
	for line in body.lines() {
		assert!(
			!line.to_ascii_lowercase().starts_with("bcc:"),
			"forged Bcc: must not appear via source-IP injection: {line:?}\n--- full body ---\n{body}"
		);
	}
}

/// `Reported-Domain:` is derived from `Original-Mail-From` after
/// sanitisation, so a CRLF in the latter cannot leak into the
/// reported-domain value either.
#[test]
fn build_sanitises_reported_domain_derived_from_mail_from() {
	let mut r = report();
	r.original_mail_from = "spammer@bad.example\r\nBcc: attacker@evil.example";
	let body = String::from_utf8(
		build(
			"mail.example.org",
			&r,
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		)
		.data,
	)
	.expect("ascii");
	let reported_line = body
		.lines()
		.find(|line| line.to_ascii_lowercase().starts_with("reported-domain:"))
		.expect("reported-domain line");
	assert!(
		!reported_line.contains('\r') && !reported_line.contains('\n'),
		"Reported-Domain: line must not contain CRLF: {reported_line:?}"
	);
}
