//! Names that Windows opens as something else, and names too large to be
//! worth reading.

use super::*;
use crate::antispam::attachments::corpus::{self, attachment};

fn inspect_default(raw: &[u8]) -> Report {
	inspect(raw, &Extensions::default(), Budget::bytes(1 << 20))
}

fn named(name: &str) -> Vec<Reason> {
	let headers = format!("Content-Type: application/octet-stream; name=\"{name}\"");
	let raw = corpus::message(&[attachment(&headers, b"hello")]);
	inspect_default(&raw).reasons()
}

#[test]
fn an_alternate_data_stream_suffix_does_not_hide_the_extension() {
	// NTFS opens `invoice.exe::$DATA` as `invoice.exe`.
	for name in [
		"invoice.exe::$DATA",
		"invoice.exe:$DATA",
		"invoice.exe:Zone.Identifier",
		"invoice.exe::$DATA.",
		"INVOICE.EXE::$data",
		"invoice.js:stream",
	] {
		assert!(
			named(name).contains(&Reason::DangerousExtension),
			"{name} was not judged dangerous"
		);
	}
}

#[test]
fn a_colon_in_an_ordinary_name_is_not_a_finding() {
	assert_eq!(named("report 12:30.txt"), vec![]);
	assert_eq!(named("notes:final.csv"), vec![]);
}

#[test]
fn a_decoy_before_a_stream_suffix_is_still_a_double_extension() {
	let reasons = named("invoice.pdf.exe::$DATA");
	assert!(reasons.contains(&Reason::DangerousExtension), "{reasons:?}");
	assert!(reasons.contains(&Reason::DoubleExtension), "{reasons:?}");
}

#[test]
fn a_name_of_megabytes_stops_the_inspection_quickly() {
	// 8 MiB of name on the first header block: it used to be folded and
	// compared byte by byte (41 s for 25 MiB) past the 10 s deadline.
	let mut raw = b"Content-Type: application/octet-stream; name=\"".to_vec();
	raw.extend(std::iter::repeat_n(b'A', 8 << 20));
	raw.extend_from_slice(b".exe\"\r\n\r\nhello\r\n");
	let started = std::time::Instant::now();
	let report = inspect_default(&raw);
	assert!(
		started.elapsed() < std::time::Duration::from_secs(2),
		"took {:?}",
		started.elapsed()
	);
	assert_eq!(report.stopped, Some(Stop::HeaderTooLarge));
	assert_eq!(report.reasons(), vec![Reason::ScanLimit]);
}

#[test]
fn a_header_block_without_its_end_is_bounded_too() {
	let mut raw = b"Content-Type: application/octet-stream; name=\"".to_vec();
	raw.extend(std::iter::repeat_n(b'A', 8 << 20));
	raw.extend_from_slice(b".exe\"");
	let started = std::time::Instant::now();
	let report = inspect_default(&raw);
	assert!(started.elapsed() < std::time::Duration::from_secs(2));
	assert_eq!(report.stopped, Some(Stop::HeaderTooLarge));
}
