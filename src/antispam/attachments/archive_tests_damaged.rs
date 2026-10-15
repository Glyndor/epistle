//! Zips that two extractors read differently, or that cannot be read to
//! the end: none of them may come out as a clean listing.

use super::*;
use crate::antispam::attachments::corpus::{self, ZipEntry};

fn find(bytes: &[u8], needle: &[u8]) -> usize {
	bytes
		.windows(needle.len())
		.position(|window| window == needle)
		.expect("needle present")
}

#[test]
fn a_local_name_that_differs_from_the_central_one_counts_too() {
	let mut zip = corpus::zip_of(&["aaaaa.txt"]);
	zip[30 + 6..30 + 9].copy_from_slice(b"exe");
	let listing = list_zip(&zip);
	assert!(listing.names.iter().any(|name| name == "aaaaa.exe"));
	assert!(listing.names.iter().any(|name| name == "aaaaa.txt"));
	assert!(listing.unreadable);
}

#[test]
fn a_file_only_the_local_headers_list_is_found() {
	let big = corpus::zip_of(&["a.txt", "evil.js"]);
	let small = corpus::zip_of(&["a.txt"]);
	let mut zip = big[..find(&big, b"PK\x01\x02")].to_vec();
	zip.extend_from_slice(&small[find(&small, b"PK\x01\x02")..]);
	let listing = list_zip(&zip);
	assert!(
		listing.names.iter().any(|name| name == "evil.js"),
		"{listing:?}"
	);
	assert!(listing.unreadable);
}

#[test]
fn an_unknown_compression_method_is_unreadable() {
	let mut zip = corpus::zip_of(&["a.txt"]);
	let central = find(&zip, b"PK\x01\x02");
	zip[8..10].copy_from_slice(&77u16.to_le_bytes());
	zip[central + 10..central + 12].copy_from_slice(&77u16.to_le_bytes());
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["a.txt"]);
	assert!(listing.unreadable);
}

#[test]
fn encryption_on_some_files_only_is_unreadable() {
	let zip = corpus::zip(&[
		ZipEntry {
			name: "readme.txt",
			encrypted: false,
		},
		ZipEntry {
			name: "payload.pdf",
			encrypted: true,
		},
	]);
	let listing = list_zip(&zip);
	assert!(listing.encrypted);
	assert!(listing.unreadable);
	let all = corpus::zip(&[ZipEntry {
		name: "payload.pdf",
		encrypted: true,
	}]);
	assert!(!list_zip(&all).unreadable);
}

#[test]
fn a_directory_that_declares_more_entries_than_it_holds_is_unreadable() {
	let mut zip = corpus::zip_of(&["a.txt", "b.txt"]);
	let end = find(&zip, b"PK\x05\x06");
	zip[end + 10..end + 12].copy_from_slice(&3u16.to_le_bytes());
	assert!(list_zip(&zip).unreadable);
	assert!(!list_zip(&corpus::zip_of(&["a.txt", "b.txt"])).unreadable);
}

#[test]
fn data_in_front_of_the_archive_is_unreadable_but_still_listed() {
	let mut zip = b"GIF89a padding in front".to_vec();
	zip.extend_from_slice(&corpus::zip_of(&["x.js"]));
	assert!(has_end_record(&zip));
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["x.js"]);
	assert!(listing.unreadable);
}

#[test]
fn a_zip64_directory_is_followed() {
	let plain = corpus::zip_of(&["x.vbs"]);
	let end = find(&plain, b"PK\x05\x06");
	let central = find(&plain, b"PK\x01\x02");
	let mut zip = plain[..end].to_vec();
	let record = zip.len() as u64;
	zip.extend_from_slice(b"PK\x06\x06");
	zip.extend_from_slice(&44u64.to_le_bytes());
	zip.extend_from_slice(&[45, 0, 45, 0]);
	zip.extend_from_slice(&[0; 8]);
	zip.extend_from_slice(&1u64.to_le_bytes());
	zip.extend_from_slice(&1u64.to_le_bytes());
	zip.extend_from_slice(&((end - central) as u64).to_le_bytes());
	zip.extend_from_slice(&(central as u64).to_le_bytes());
	zip.extend_from_slice(b"PK\x06\x07");
	zip.extend_from_slice(&[0; 4]);
	zip.extend_from_slice(&record.to_le_bytes());
	zip.extend_from_slice(&1u32.to_le_bytes());
	zip.extend_from_slice(b"PK\x05\x06");
	zip.extend_from_slice(&[0; 4]);
	zip.extend_from_slice(&[0xff; 4]);
	zip.extend_from_slice(&[0xff; 8]);
	zip.extend_from_slice(&[0; 2]);
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["x.vbs"]);
	assert!(!listing.unreadable, "{listing:?}");
}

#[test]
fn local_headers_with_data_descriptors_are_walked_to_the_next_signature() {
	let mut zip = corpus::zip_of(&["a.txt", "b.exe"]);
	zip.truncate(find(&zip, b"PK\x01\x02"));
	zip[6] |= 0x08;
	zip[18..22].copy_from_slice(&0u32.to_le_bytes());
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["a.txt", "b.exe"]);
	assert!(listing.unreadable);
}

#[test]
fn a_zip_signature_followed_by_garbage_is_unreadable() {
	let listing = list_zip(b"PK\x03\x04 garbage that is not a header");
	assert!(listing.names.is_empty());
	assert!(listing.unreadable);
}
