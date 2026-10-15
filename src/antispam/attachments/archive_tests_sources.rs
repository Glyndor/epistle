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
fn a_directory_offset_read_without_the_shift_is_read_too() {
	let listing = list_zip(&offset_into_prefixed_data());
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
fn a_legacy_code_page_name_is_read_both_ways() {
	let listing = list_zip(&corpus::zip_raw(&[RawEntry {
		name: b"r\x82sum\x82.exe",
		flags: 0,
		central_extra: Vec::new(),
	}]));
	assert_eq!(listing.names.len(), 2, "{listing:?}");
	assert!(listing.names.iter().all(|name| name.ends_with(".exe")));
	assert!(!listing.ambiguous);
}

#[test]
fn a_plain_zip_is_neither_ambiguous_nor_unreadable() {
	let listing = list_zip(&corpus::zip_of(&["a.txt", "b/c.pdf"]));
	assert!(!listing.ambiguous && !listing.unreadable, "{listing:?}");
}
