//! A report quotes the headers of the message it is about, whatever bytes
//! they hold and wherever the quote is cut: what comes out always fits the
//! queue.

use super::*;
use std::time::{Duration, UNIX_EPOCH};

const POISON: [&[u8]; 6] = [b"\r", b"\0", b"\r\r\n", b"\n", b"\r\0\n", b"\r."];

/// Headers whose block is longer than the cap, with `poison` starting at
/// `at`, and a body after them.
fn original(at: usize, poison: &[u8]) -> Vec<u8> {
	let mut data = b"From: alice@example.org\r\nX-Pad: ".to_vec();
	data.resize(at, b'x');
	data.extend_from_slice(poison);
	while data.len() < 6000 {
		data.extend_from_slice(b"\r\nX-More: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");
	}
	data.extend_from_slice(b"\r\n\r\nsecret body\r\n");
	data
}

fn now() -> std::time::SystemTime {
	UNIX_EPOCH + Duration::from_secs(1_780_662_896)
}

fn recipients() -> Vec<ReportRecipient> {
	vec![ReportRecipient::new(
		"bob@elsewhere.example",
		"550 5.1.1 no\rsuch\0user",
	)]
}

#[test]
fn every_report_built_from_headers_cut_anywhere_near_the_cap_fits_the_queue() {
	for at in 4080..=4110 {
		for poison in POISON {
			let data = original(at, poison);
			let reports = [
				build_failed(
					"mail.example.org",
					"alice@example.org",
					&recipients(),
					&data,
					now(),
					true,
				),
				build_delay_warning(
					"mail.example.org",
					"alice@example.org",
					&recipients(),
					&data,
					now(),
					true,
				),
				build(
					"mail.example.org",
					"alice@example.org",
					&["bob@elsewhere.example".to_string()],
					"550 no",
					&data,
					now(),
					false,
				),
			];
			for report in reports {
				let report = report.expect("report built");
				assert!(
					!crate::util::header_block::has_unframed_byte(&report.data),
					"at {at}, poison {poison:?}"
				);
				let dir = tempfile::tempdir().expect("tempdir");
				let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
				spool
					.store(&report, None, &std::collections::BTreeMap::new())
					.unwrap_or_else(|error| panic!("at {at}, poison {poison:?}: {error}"));
			}
		}
	}
}

#[test]
fn the_quoted_headers_end_on_a_whole_line() {
	let data = original(4095, b"\r");
	let quoted = original_header_block(&data);
	assert!(quoted.len() <= 4096);
	assert!(quoted.ends_with('\n'), "{quoted:?}");
	assert!(!quoted.contains("\r\r"));
}

#[test]
fn a_sender_that_would_open_a_header_gets_no_report() {
	for sender in [
		"alice@example.org>\r\nBcc: victim@example.net",
		"alice@example.org\nBcc: victim@example.net",
		"alice@exam\0ple.org",
		"<alice@example.org>",
	] {
		let report = build_failed(
			"mail.example.org",
			sender,
			&recipients(),
			&original(4000, b""),
			now(),
			true,
		);
		assert!(report.is_none(), "{sender:?}");
	}
}
