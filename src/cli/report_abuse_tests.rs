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
