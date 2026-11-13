//! A report is not written for a report, and its parts cannot be opened
//! from the headers it quotes.

use super::*;
use std::time::{Duration, UNIX_EPOCH};

fn now() -> std::time::SystemTime {
	UNIX_EPOCH + Duration::from_secs(1_780_662_896)
}

fn bounce_of(original: &[u8]) -> Option<AcceptedMessage> {
	build(
		"mail.example.org",
		"mailer-daemon@elsewhere.example",
		&["bob@elsewhere.example".to_string()],
		"550 5.1.1 no such user",
		original,
		now(),
		true,
	)
}

#[test]
fn a_delivery_status_report_with_a_return_path_gets_no_report() {
	let report = b"From: MAILER-DAEMON@elsewhere.example\r\n\
Content-Type: multipart/report; report-type=delivery-status;\r\n\x20boundary=\"x\"\r\n\r\nbody\r\n";
	assert!(bounce_of(report).is_none());
}

#[test]
fn the_content_type_is_read_whatever_its_case_and_folding() {
	let report = b"From: a@b.example\r\ncontent-TYPE:\r\n\tMultipart/Report;\r\n\x20Report-Type=Delivery-Status\r\n\r\nbody\r\n";
	assert!(bounce_of(report).is_none());
}

#[test]
fn an_ordinary_message_and_a_report_of_another_kind_still_get_one() {
	let mixed =
		b"From: a@b.example\r\nContent-Type: multipart/mixed; boundary=\"x\"\r\n\r\nbody\r\n";
	assert!(bounce_of(mixed).is_some());
	let disposition = b"From: a@b.example\r\n\
Content-Type: multipart/report; report-type=disposition-notification\r\n\r\nbody\r\n";
	assert!(bounce_of(disposition).is_some());
}

#[test]
fn a_header_of_the_original_cannot_name_the_boundary_of_the_report() {
	let boundaries = |original: &[u8]| -> Vec<String> {
		let bounce = bounce_of(original).expect("report");
		let text = String::from_utf8(bounce.data).expect("ascii");
		text.lines()
			.filter_map(|line| line.strip_prefix("--=_dsn_"))
			.map(str::to_string)
			.collect()
	};
	let original = b"From: a@b.example\r\nSubject: x\r\n\r\nbody\r\n";
	let first = boundaries(original);
	let second = boundaries(original);
	assert!(!first.is_empty());
	assert_ne!(
		first, second,
		"two reports at the same second share a boundary"
	);
	let guessed = format!("{}", 1_780_662_896_u64);
	assert!(
		first.iter().all(|b| *b != guessed),
		"the boundary is the clock second"
	);
}
