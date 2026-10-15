//! Zips whose name sources disagree: every source is listed and the
//! disagreement is reported.

use super::*;
use crate::antispam::attachments::corpus::{self, RawEntry};

fn find(bytes: &[u8], needle: &[u8]) -> usize {
	bytes
		.windows(needle.len())
		.position(|window| window == needle)
		.expect("needle present")
}

/// A real zip listing `a.txt` whose archive comment holds a second central
/// record for `evil.js` and a fake end record pointing at it. Extractors
/// that scan backwards for the end record find the fake one first.
pub(crate) fn fake_end_record_in_comment() -> Vec<u8> {
	let real = corpus::zip_of(&["a.txt"]);
	let evil = corpus::zip_of(&["evil.js"]);
	let evil_central = &evil[find(&evil, b"PK\x01\x02")..find(&evil, b"PK\x05\x06")];
	let body = &real[..real.len() - 2];
	let central_at = body.len() + 2;
	let mut comment = evil_central.to_vec();
	comment.extend_from_slice(b"PK\x05\x06");
	comment.extend_from_slice(&[0; 4]);
	comment.extend_from_slice(&1u16.to_le_bytes());
	comment.extend_from_slice(&1u16.to_le_bytes());
	comment.extend_from_slice(&(evil_central.len() as u32).to_le_bytes());
	comment.extend_from_slice(&(central_at as u32).to_le_bytes());
	comment.extend_from_slice(&0u16.to_le_bytes());
	let mut zip = body.to_vec();
	zip.extend_from_slice(&(comment.len() as u16).to_le_bytes());
	zip.extend_from_slice(&comment);
	zip
}

/// A real zip listing `a.txt` with a fake directory for `evil.js` and its
/// own end record sitting before the real directory. Extractors that scan
/// forward for the end record take the fake one.
pub(crate) fn earlier_fake_end_record() -> Vec<u8> {
	let real = corpus::zip_of(&["a.txt"]);
	let evil = corpus::zip_of(&["evil.js"]);
	let evil_central = &evil[find(&evil, b"PK\x01\x02")..find(&evil, b"PK\x05\x06")];
	let directory = find(&real, b"PK\x01\x02");
	let mut fake = evil_central.to_vec();
	fake.extend_from_slice(b"PK\x05\x06");
	fake.extend_from_slice(&[0; 4]);
	fake.extend_from_slice(&1u16.to_le_bytes());
	fake.extend_from_slice(&1u16.to_le_bytes());
	fake.extend_from_slice(&(evil_central.len() as u32).to_le_bytes());
	fake.extend_from_slice(&(directory as u32).to_le_bytes());
	fake.extend_from_slice(&0u16.to_le_bytes());
	let mut zip = real[..directory].to_vec();
	zip.extend_from_slice(&fake);
	zip.extend_from_slice(&real[directory..]);
	let end = zip.len() - 22;
	let moved = (directory + fake.len()) as u32;
	zip[end + 16..end + 20].copy_from_slice(&moved.to_le_bytes());
	zip
}

/// Data in front of a zip whose directory offset, read without the shift,
/// lands on a central record for `evil.js` planted in that data.
pub(crate) fn offset_into_prefixed_data() -> Vec<u8> {
	let real = corpus::zip_of(&["a.txt"]);
	let evil = corpus::zip_of(&["evil.js"]);
	let evil_central = &evil[find(&evil, b"PK\x01\x02")..find(&evil, b"PK\x05\x06")];
	let declared = find(&real, b"PK\x01\x02");
	let mut prefix = vec![b' '; declared];
	prefix.extend_from_slice(evil_central);
	prefix.extend_from_slice(b"padding after the planted record");
	prefix.extend_from_slice(&real);
	prefix
}

/// A zip whose central record names `readme.txt` and carries a Unicode
/// Path field naming `invoice.exe`.
pub(crate) fn unicode_path_differs() -> Vec<u8> {
	let path = b"invoice.exe";
	let mut extra = 0x7075u16.to_le_bytes().to_vec();
	extra.extend_from_slice(&((5 + path.len()) as u16).to_le_bytes());
	extra.push(1);
	extra.extend_from_slice(&[0; 4]);
	extra.extend_from_slice(path);
	corpus::zip_raw(&[RawEntry {
		name: b"readme.txt",
		flags: 0,
		central_extra: extra,
	}])
}

#[test]
fn a_fake_end_record_in_the_comment_is_read_too() {
	let listing = list_zip(&fake_end_record_in_comment());
	assert!(
		listing.names.iter().any(|name| name == "a.txt"),
		"{listing:?}"
	);
	assert!(
		listing.names.iter().any(|name| name == "evil.js"),
		"{listing:?}"
	);
	assert!(listing.ambiguous);
}

#[test]
fn an_earlier_end_record_is_read_too() {
	let listing = list_zip(&earlier_fake_end_record());
	assert!(
		listing.names.iter().any(|name| name == "a.txt"),
		"{listing:?}"
	);
	assert!(
		listing.names.iter().any(|name| name == "evil.js"),
		"{listing:?}"
	);
	assert!(listing.ambiguous);
}

#[test]
fn a_directory_offset_that_does_not_match_is_ambiguous() {
	let listing = list_zip(&offset_into_prefixed_data());
	assert!(
		listing.names.iter().any(|name| name == "a.txt"),
		"{listing:?}"
	);
	assert!(listing.ambiguous);
}

#[test]
fn a_unicode_path_field_is_a_name_too() {
	let listing = list_zip(&unicode_path_differs());
	assert!(
		listing.names.iter().any(|name| name == "invoice.exe"),
		"{listing:?}"
	);
	assert!(listing.ambiguous);
}

#[test]
fn a_name_that_claims_utf8_and_is_not_is_ambiguous() {
	let listing = list_zip(&corpus::zip_raw(&[RawEntry {
		name: b"a\xff.exe",
		flags: 0x0800,
		central_extra: Vec::new(),
	}]));
	assert!(listing.ambiguous, "{listing:?}");
}

#[test]
fn a_legacy_name_is_also_read_as_code_page_437() {
	let listing = list_zip(&corpus::zip_raw(&[RawEntry {
		name: b"r\x82sum\x82.exe",
		flags: 0,
		central_extra: Vec::new(),
	}]));
	assert!(
		listing.names.iter().any(|name| name == "résumé.exe"),
		"{listing:?}"
	);
	assert!(!listing.ambiguous);
}

#[test]
fn a_cut_name_keeps_its_extension_and_is_ambiguous() {
	let mut name = vec![b'a'; 1100];
	name.extend_from_slice(b".exe");
	let listing = list_zip(&corpus::zip_raw(&[RawEntry {
		name: &name,
		flags: 0,
		central_extra: Vec::new(),
	}]));
	assert!(
		listing.names.iter().all(|name| name.ends_with(".exe")),
		"{:?}",
		listing.names.len()
	);
	assert!(listing.ambiguous);
}

#[test]
fn data_in_front_larger_than_the_window_is_ambiguous() {
	let plain = corpus::zip_of(&["a.txt"]);
	let prefix = vec![b' '; 70 * 1024];
	let shift = prefix.len() as u32;
	let mut zip = prefix;
	zip.extend_from_slice(&plain);
	let central = find(&zip, b"PK\x01\x02");
	let local_offset = central + 42;
	let old = u32::from_le_bytes(zip[local_offset..local_offset + 4].try_into().unwrap());
	zip[local_offset..local_offset + 4].copy_from_slice(&(old + shift).to_le_bytes());
	let end = zip.len() - 22;
	let old = u32::from_le_bytes(zip[end + 16..end + 20].try_into().unwrap());
	zip[end + 16..end + 20].copy_from_slice(&(old + shift).to_le_bytes());
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["a.txt"]);
	assert!(listing.ambiguous, "{listing:?}");
}

#[test]
fn a_directory_pointing_at_no_local_header_is_ambiguous() {
	let mut zip = corpus::zip_of(&["a.txt"]);
	let central = find(&zip, b"PK\x01\x02");
	zip[central + 42..central + 46].copy_from_slice(&7u32.to_le_bytes());
	let listing = list_zip(&zip);
	assert!(listing.unreadable && listing.ambiguous, "{listing:?}");
}

#[test]
fn a_unicode_path_field_is_ambiguous_even_when_it_agrees() {
	let mut extra = 0x7075u16.to_le_bytes().to_vec();
	extra.extend_from_slice(&((5 + 8) as u16).to_le_bytes());
	extra.push(1);
	extra.extend_from_slice(&[0; 4]);
	extra.extend_from_slice(b"same.txt");
	let listing = list_zip(&corpus::zip_raw(&[RawEntry {
		name: b"same.txt",
		flags: 0,
		central_extra: extra,
	}]));
	assert_eq!(listing.names, vec!["same.txt"]);
	assert!(listing.ambiguous);
}

#[test]
fn more_than_four_end_records_is_ambiguous_and_the_scan_stays_in_the_tail() {
	let mut zip = corpus::zip_of(&["a.txt"]);
	let comment: Vec<u8> = b"PK\x05\x06".repeat(10);
	let len = zip.len();
	zip[len - 2..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
	zip.extend_from_slice(&comment);
	let listing = list_zip(&zip);
	assert!(listing.ambiguous, "{listing:?}");
	assert_eq!(super::end_records(&zip).len(), MAX_END_RECORDS + 1);
}

#[test]
fn a_file_full_of_fake_signatures_is_read_in_linear_time() {
	let pattern = b"PK\x05\x06PK\x03\x04PK\x01\x02\x08\x00";
	let mut sizes = Vec::new();
	for size in [1usize << 20, 25 << 20] {
		let file: Vec<u8> = pattern.iter().copied().cycle().take(size).collect();
		let started = std::time::Instant::now();
		let listing = list_zip(&file);
		let _ = has_end_record(&file);
		sizes.push(started.elapsed());
		assert!(
			listing.ambiguous || listing.unreadable,
			"{:?}",
			listing.names.len()
		);
	}
	assert!(
		sizes[1] < std::time::Duration::from_secs(5),
		"25 MiB took {:?}",
		sizes[1]
	);
}

#[test]
fn a_plain_zip_is_neither_ambiguous_nor_unreadable() {
	let listing = list_zip(&corpus::zip_of(&["a.txt", "b/c.pdf"]));
	assert!(!listing.ambiguous && !listing.unreadable, "{listing:?}");
}

#[test]
fn records_past_the_shared_cap_are_a_scan_limit() {
	let entries: Vec<RawEntry<'_>> = (0..10_001)
		.map(|_| RawEntry {
			name: b"a.txt",
			flags: 0,
			central_extra: Vec::new(),
		})
		.collect();
	let listing = list_zip(&corpus::zip_raw(&entries));
	assert_eq!(listing.names, vec!["a.txt"]);
	assert!(listing.too_many, "repeated records still count");
}

#[test]
fn data_in_front_of_the_first_local_header_is_ambiguous_even_with_fixed_offsets() {
	let plain = corpus::zip_of(&["a.txt"]);
	let prefix = b"self-extractor stub ".to_vec();
	let shift = prefix.len() as u32;
	let mut zip = prefix;
	zip.extend_from_slice(&plain);
	let central = find(&zip, b"PK\x01\x02");
	let local_offset = central + 42;
	let old = u32::from_le_bytes(zip[local_offset..local_offset + 4].try_into().unwrap());
	zip[local_offset..local_offset + 4].copy_from_slice(&(old + shift).to_le_bytes());
	let end = zip.len() - 22;
	let old = u32::from_le_bytes(zip[end + 16..end + 20].try_into().unwrap());
	zip[end + 16..end + 20].copy_from_slice(&(old + shift).to_le_bytes());
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["a.txt"]);
	assert!(!listing.unreadable, "{listing:?}");
	assert!(listing.ambiguous, "{listing:?}");
}

#[test]
fn a_nul_in_the_cut_middle_of_a_long_name_still_ends_a_reading() {
	// A C extractor stops at the NUL and writes `xxx...x.exe`; the cut
	// keeps the head and the tail and drops the NUL with the middle.
	let mut name = vec![b'x'; 795];
	name.extend_from_slice(b".exe\0");
	name.extend_from_slice(&[b'y'; 1000]);
	name.extend_from_slice(b".pdf");
	let zip = corpus::zip_raw(&[RawEntry {
		name: &name,
		flags: 0,
		central_extra: Vec::new(),
	}]);
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: application/zip; name=\"a.zip\"",
		&zip,
	)]);
	let reasons = crate::antispam::attachments::inspect(
		&raw,
		&crate::antispam::attachments::rules::Extensions::default(),
		crate::antispam::attachments::Budget::bytes(1 << 20),
	)
	.reasons();
	assert!(
		reasons.contains(&crate::antispam::attachments::rules::Reason::DangerousArchiveEntry),
		"{reasons:?}"
	);
	assert!(reasons.contains(&crate::antispam::attachments::rules::Reason::AmbiguousArchive));
}
