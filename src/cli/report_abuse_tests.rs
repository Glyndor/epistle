//! Tests for the RFC 5965 ARF abuse-report generator.

use super::*;
use std::io::Cursor;

fn config() -> Config {
	toml::from_str("hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n")
		.expect("config parses")
}

const OFFENDING: &[u8] = b"Return-Path: <spammer@bad.example>\r\n\
Received: from bad.example ([192.0.2.55]) by mail.example.org\r\n\
From: Spammer <spammer@bad.example>\r\n\
Date: Mon, 1 Jun 2026 10:00:00 +0000\r\n\
Subject: Buy now\r\n\r\nspam body\r\n";

#[test]
fn emits_arf_report() {
	let mut out = Vec::new();
	assert_eq!(
		run(&config(), Cursor::new(OFFENDING), &mut out),
		ExitCode::SUCCESS
	);
	let report = String::from_utf8(out).expect("utf8");
	assert!(
		report.contains("multipart/report; report-type=feedback-report"),
		"{report}"
	);
	assert!(report.contains("message/feedback-report"), "{report}");
	assert!(report.contains("Feedback-Type: abuse"), "{report}");
	assert!(report.contains("Version: 1"), "{report}");
	assert!(
		report.contains("Original-Mail-From: <spammer@bad.example>"),
		"{report}"
	);
	assert!(report.contains("Source-IP: 192.0.2.55"), "{report}");
	assert!(
		report.contains("Arrival-Date: Mon, 1 Jun 2026 10:00:00 +0000"),
		"{report}"
	);
	// The original message is embedded and the report is closed.
	assert!(report.contains("message/rfc822"), "{report}");
	assert!(report.contains("spam body"), "{report}");
	assert!(report.trim_end().ends_with("--"), "{report}");
}

#[test]
fn empty_input_fails() {
	let mut out = Vec::new();
	assert_eq!(
		run(&config(), Cursor::new(&b""[..]), &mut out),
		ExitCode::FAILURE
	);
	assert!(out.is_empty());
}

#[test]
fn header_lookup_is_case_insensitive() {
	let msg = "FROM: a@b.example\r\n\r\nbody";
	assert_eq!(header(msg, "from").as_deref(), Some("a@b.example"));
	assert_eq!(header(msg, "missing"), None);
}

/// The reported message is hostile input by definition. A CRLF in
/// `Return-Path:` would, if interpolated raw into the ARF report,
/// terminate the `Original-Mail-From:` line and let the spammers forge
/// headers (`Bcc:`, `X-*:`, …) into the abuse report the operator sends
/// to the offending sender's abuse contact. The report must sanitise:
/// the CRLF is collapsed to a space, so the resulting line is one header
/// line and the `Bcc:` content is opaque text on it, not a new header.
///
/// The scan covers only the outer envelope and the feedback-report block
/// — the embedded `message/rfc822` part is the offender's mail verbatim
/// and is never parsed as headers by this code.
#[test]
fn arf_report_sanitises_crlf_in_return_path() {
	let hostile = b"Return-Path: <spammer@bad.example\r\nBcc: attacker@evil.example>\r\n\
Received: from bad.example ([192.0.2.55]) by mail.example.org\r\n\
Subject: Buy now\r\n\r\nspam body\r\n";
	let mut out = Vec::new();
	assert_eq!(
		run(&config(), Cursor::new(&hostile[..]), &mut out),
		ExitCode::SUCCESS
	);
	let report = String::from_utf8(out).expect("utf8");
	// Slice off the embedded original message (it appears after the
	// `message/rfc822` part header).
	let envelope = report
		.split("\r\nContent-Type: message/rfc822")
		.next()
		.unwrap_or(&report);
	for line in envelope.lines() {
		assert!(
			!line.to_ascii_lowercase().starts_with("bcc:"),
			"forged Bcc: must not appear as its own header in the outer envelope: {line:?}\n--- envelope ---\n{envelope}"
		);
	}
}

/// Same protection for the `Source-IP:` extracted from `Received:`: a CR
/// inside the bracketed token (CR alone does not terminate a line in our
/// parser — only CRLF or LF does) would split the `Source-IP:` value once
/// it reaches `format!` and start a new header.
#[test]
fn arf_report_sanitises_crlf_in_received_ip() {
	// The bracketed token the parser extracts is everything between the
	// first `[` and the matching `]`. Embedding `CR + Bcc:` inside that
	// token (CR alone does NOT split a line in Rust's `lines()`, so the
	// parser still extracts the whole thing) gives the sanitiser a value
	// to collapse.
	let hostile = b"Return-Path: <spammer@bad.example>\r\n\
Received: from bad.example ([192.0.2.55\rBcc: attacker@evil.example]) by mail.example.org\r\n\
Subject: Buy now\r\n\r\nspam body\r\n";
	let mut out = Vec::new();
	assert_eq!(
		run(&config(), Cursor::new(&hostile[..]), &mut out),
		ExitCode::SUCCESS
	);
	let report = String::from_utf8(out).expect("utf8");
	let envelope = report
		.split("\r\nContent-Type: message/rfc822")
		.next()
		.unwrap_or(&report);
	for line in envelope.lines() {
		assert!(
			!line.to_ascii_lowercase().starts_with("bcc:"),
			"forged Bcc: must not appear via received-IP injection: {line:?}\n--- envelope ---\n{envelope}"
		);
	}
}
