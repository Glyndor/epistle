//! Whatever could not be inspected completely is never reported clean.

use super::*;
use crate::antispam::attachments::corpus::{self, attachment};

fn inspect_default(raw: &[u8]) -> Report {
	inspect(raw, &Extensions::default(), Budget::bytes(1 << 20))
}

fn reasons_of(raw: &[u8]) -> Vec<Reason> {
	inspect_default(raw).reasons()
}

#[test]
fn a_payload_past_the_part_cap_is_a_scan_limit() {
	let mut raw = String::from("Content-Type: multipart/mixed; boundary=p\r\n\r\n");
	for _ in 0..MAX_PARTS {
		raw.push_str("--p\r\nContent-Type: text/plain\r\n\r\nharmless\r\n");
	}
	raw.push_str(
		"--p\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--p--\r\n",
	);
	assert_eq!(reasons_of(raw.as_bytes()), vec![Reason::ScanLimit]);
}

#[test]
fn a_passed_deadline_is_a_scan_limit() {
	let raw = corpus::message(&[attachment(
		"Content-Type: image/png; name=a.png",
		&corpus::png(),
	)]);
	let budget = Budget {
		max_decoded: 1 << 20,
		deadline: Some(std::time::Instant::now()),
	};
	let report = inspect(&raw, &Extensions::default(), budget);
	assert_eq!(report.stopped, Some(Stop::OutOfTime));
	assert_eq!(report.reasons(), vec![Reason::ScanLimit]);
}

#[test]
fn a_part_cut_by_the_byte_budget_is_sniffed_and_still_a_scan_limit() {
	let mut payload = corpus::pe();
	payload.resize(200_000, b'A');
	let raw = corpus::message(&[attachment("Content-Type: image/jpeg; name=a.jpg", &payload)]);
	let report = inspect(&raw, &Extensions::default(), Budget::bytes(1000));
	assert_eq!(report.parts.len(), 1);
	assert_eq!(
		report.parts[0].real_type,
		RealType::Pe,
		"the prefix is sniffed"
	);
	assert_eq!(
		report.parts[0].reasons,
		vec![
			Reason::ExecutableContent,
			Reason::TypeMismatch,
			Reason::ScanLimit
		]
	);
}

#[test]
fn uuencoded_blocks_past_the_cap_are_a_scan_limit() {
	let block = corpus::uu("note.txt", b"plain");
	let raw = format!(
		"Content-Type: text/plain\r\n\r\n{}",
		block.repeat(decode::MAX_EMBEDDED + 1)
	);
	assert_eq!(reasons_of(raw.as_bytes()), vec![Reason::ScanLimit]);
}

#[test]
fn rar_and_7z_cannot_be_listed_so_they_are_unreadable() {
	let raw = corpus::message(&[
		attachment(
			"Content-Type: application/x-rar; name=a.rar",
			b"Rar!\x1a\x07\x01\x00data",
		),
		attachment(
			"Content-Type: application/x-7z; name=b.7z",
			b"7z\xbc\xaf\x27\x1c\x00\x04",
		),
	]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts.len(), 2);
	for part in &report.parts {
		assert_eq!(part.reasons, vec![Reason::UnreadableArchive]);
	}
}

#[test]
fn an_archive_inside_an_archive_is_flagged() {
	let raw = corpus::message(&[attachment(
		"Content-Type: application/zip; name=outer.zip",
		&corpus::zip_of(&["docs/inner.ZIP", "readme.txt"]),
	)]);
	assert_eq!(reasons_of(&raw), vec![Reason::NestedArchive]);
}

#[test]
fn a_nul_in_an_entry_name_does_not_hide_its_extension() {
	let raw = corpus::message(&[attachment(
		"Content-Type: application/zip; name=a.zip",
		&corpus::zip_of(&["invoice.exe\0.txt"]),
	)]);
	assert_eq!(reasons_of(&raw), vec![Reason::DangerousArchiveEntry]);
}

#[test]
fn a_zip_with_data_in_front_is_still_opened() {
	let mut payload = b"not a zip signature ".to_vec();
	payload.extend_from_slice(&corpus::zip_of(&["run.js"]));
	let raw = corpus::message(&[attachment(
		"Content-Type: application/octet-stream; name=a.dat",
		&payload,
	)]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts[0].real_type, RealType::Zip);
	assert_eq!(
		report.parts[0].reasons,
		vec![Reason::DangerousArchiveEntry, Reason::UnreadableArchive]
	);
}

#[test]
fn an_image_or_pdf_the_bytes_do_not_confirm_is_a_mismatch() {
	let raw = corpus::message(&[
		attachment(
			"Content-Type: image/jpeg; name=photo.jpg",
			b"plain bytes, not a jpeg",
		),
		attachment(
			"Content-Type: application/pdf; name=scan.pdf",
			b"plain bytes, not a pdf",
		),
		attachment(
			"Content-Type: image/svg+xml; name=logo.svgz",
			b"\x1f\x8b compressed svg",
		),
	]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts.len(), 3);
	assert_eq!(report.parts[0].reasons, vec![Reason::TypeMismatch]);
	assert_eq!(report.parts[1].reasons, vec![Reason::TypeMismatch]);
	assert!(
		report.parts[2].reasons.is_empty(),
		"no signature to check svgz against"
	);
}

#[test]
fn a_text_part_whose_bytes_are_a_program_is_caught() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAA=\r\n--b\r\n\
		Content-Type: text/plain\r\n\r\nBMW meeting notes, nothing binary\r\n--b--\r\n";
	let report = inspect_default(raw);
	assert_eq!(report.parts.len(), 1, "{report:?}");
	assert_eq!(report.parts[0].real_type, RealType::Pe);
	assert_eq!(
		report.parts[0].reasons,
		vec![Reason::ExecutableContent, Reason::TypeMismatch]
	);
}

#[test]
fn quoted_printable_soft_breaks_and_invalid_escapes_read_like_a_client() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: application/octet-stream; name=a.bin\r\n\
		Content-Transfer-Encoding: quoted-printable\r\n\r\nM=\r\nZ=90=ZZ=3d \r\n--b--\r\n";
	let mut found = Vec::new();
	let limits = walk::Limits {
		max_depth: MAX_DEPTH,
		max_parts: MAX_PARTS,
		max_decoded: 1 << 20,
		deadline: None,
	};
	walk::walk(raw, &limits, |leaf| found.push(leaf));
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].content, b"MZ\x90=ZZ= ");
	assert!(found[0].ambiguous, "an invalid escape reads two ways");
}

#[test]
fn transfer_encoding_variants_decode_and_odd_ones_are_flagged() {
	for (value, ambiguous) in [
		("BASE64", false),
		("  Base64  ", false),
		("\"base64\"", true),
		("base64; x=y", true),
	] {
		let raw = format!(
			"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
			 Content-Type: application/octet-stream; name=a.bin\r\n\
			 Content-Transfer-Encoding: {value}\r\n\r\nTVqQAA==\r\n--b--\r\n"
		);
		let report = inspect_default(raw.as_bytes());
		assert_eq!(report.parts.len(), 1, "{value}");
		assert_eq!(report.parts[0].real_type, RealType::Pe, "{value}");
		assert_eq!(
			report.parts[0].reasons.contains(&Reason::AmbiguousMime),
			ambiguous,
			"{value}"
		);
	}
}
