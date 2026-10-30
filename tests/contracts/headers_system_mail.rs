//! The "System mail" table of `docs/headers.md` lists the top-level headers
//! of each message the server writes by itself. This builds each message with
//! the real builder and compares, so the table cannot drift from the code.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use epistle::antispam::arf::{self, FeedbackType};
use epistle::queue::bounce::{self, ReportRecipient};
use epistle::sieve::vacation::{self, Original, Vacation};

fn now() -> SystemTime {
	SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

/// The header names (as written) of the top-level block of `message`.
fn header_names(message: &[u8]) -> BTreeSet<String> {
	let text = String::from_utf8_lossy(message);
	let mut names = BTreeSet::new();
	for line in text.split("\r\n") {
		if line.is_empty() {
			break;
		}
		if line.starts_with([' ', '\t']) {
			continue;
		}
		let (name, _) = line.split_once(':').expect("a header line");
		names.insert(name.to_string());
	}
	names
}

/// The rows of the "System mail" table: label, and the names in backticks.
fn documented() -> Vec<(String, BTreeSet<String>)> {
	let page = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/headers.md"))
		.expect("read docs/headers.md");
	let section = page
		.split("\n## ")
		.find(|section| section.starts_with("System mail"))
		.expect("the System mail section");
	let mut rows = Vec::new();
	for line in section.lines().filter(|line| line.starts_with("| ")) {
		let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
		if cells.len() != 2 || cells[0] == "Message" || cells[0].starts_with("---") {
			continue;
		}
		let names = cells[1]
			.split('`')
			.skip(1)
			.step_by(2)
			.map(str::to_string)
			.collect();
		rows.push((cells[0].to_string(), names));
	}
	rows
}

/// The value RFC 3834 section 5 gives a message the server wrote itself.
/// Every system message here is machine-generated, so this is the value
/// they all carry (a vacation reply is `auto-replied`, and its test says so).
fn expect_auto_generated(built: &[u8]) {
	let text = String::from_utf8_lossy(built);
	assert!(
		text.contains("Auto-Submitted: auto-generated"),
		"the message is not marked machine-generated: {text}"
	);
}

fn expect(label: &str, built: &[u8], added_later: &[&str]) {
	let rows = documented();
	let (_, wanted) = rows
		.iter()
		.find(|(name, _)| name == label)
		.unwrap_or_else(|| panic!("docs/headers.md has no \"{label}\" row in System mail"));
	let mut actual = header_names(built);
	actual.extend(added_later.iter().map(|name| name.to_string()));
	assert_eq!(
		&actual, wanted,
		"{label}: the message and docs/headers.md list different headers"
	);
}

const ORIGINAL: &[u8] = b"From: sender@example.net\r\nTo: rcpt@example.org\r\nSubject: hello\r\nMessage-ID: <m1@example.net>\r\n\r\nbody\r\n";

#[test]
fn a_failure_notice_has_the_documented_headers() {
	let message = bounce::build(
		"mail.example.org",
		"sender@example.net",
		&["rcpt@example.org".to_string()],
		"550 5.1.1 no such user",
		ORIGINAL,
		now(),
		true,
	)
	.expect("a notice");
	assert!(message.reverse_path.is_empty());
	expect("Failure notice", &message.data, &[]);
	expect_auto_generated(&message.data);
}

#[test]
fn a_delay_warning_has_the_documented_headers() {
	let recipients = [ReportRecipient::new(
		"rcpt@example.org",
		"451 4.7.1 try later",
	)];
	let message = bounce::build_delay_warning(
		"mail.example.org",
		"sender@example.net",
		&recipients,
		ORIGINAL,
		now(),
		true,
	)
	.expect("a warning");
	expect("Delay warning", &message.data, &[]);
	expect_auto_generated(&message.data);
}

#[test]
fn a_vacation_reply_has_the_documented_headers() {
	let vacation = Vacation {
		reason: "I am away.",
		subject: None,
		from: None,
		user_address: "me@example.org",
		html_body: None,
	};
	let original = Original {
		subject: Some("hello"),
		message_id: Some("<m1@example.net>"),
		references: None,
	};
	let message = vacation::build_response(&vacation, "sender@example.net", &original, now())
		.expect("a reply");
	assert!(message.reverse_path.is_empty());
	expect("Vacation reply", &message.data, &[]);
}

#[test]
fn an_abuse_report_has_the_documented_headers() {
	let report = arf::Report {
		report_to: "abuse@example.net",
		feedback_type: FeedbackType::Abuse,
		original_mail_from: "spam@bad.example",
		source_ip: Some("192.0.2.1"),
		reported_message: ORIGINAL,
	};
	let message = arf::build("mail.example.org", &report, now());
	expect("Abuse report", &message.data, &[]);
	expect_auto_generated(&message.data);
}

#[test]
fn a_dmarc_report_has_the_documented_headers() {
	let email = epistle::dmarc::report::build_email(
		"example.net",
		"rua@example.net",
		"report-1",
		1_789_900_000,
		1_789_986_400,
		"example.org",
		"mail.example.org",
		now(),
		b"gz",
		true,
	);
	expect("DMARC aggregate report", &email, &[]);
	expect_auto_generated(&email);
}

#[test]
fn a_tls_rpt_report_has_the_documented_headers() {
	let email = epistle::tlsrpt::report::build_email(
		"example.net",
		"tlsrpt@example.net",
		"2026-10-18.example.net@mail.example.org",
		1_789_900_000,
		1_789_986_400,
		"example.org",
		b"gz",
		true,
	);
	// The sender puts Date and Message-ID in front of this (tlsrpt/send/mod.rs).
	expect("TLS-RPT report", &email, &["Date", "Message-ID"]);
	expect_auto_generated(&email);
}
