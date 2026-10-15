use super::*;
use crate::antispam::attachments::corpus::{self, ZipEntry};

#[test]
fn entry_names_come_from_the_central_directory() {
	let listing = list_zip(&corpus::zip_of(&["readme.txt", "docs/x.js"]));
	assert_eq!(listing.names, vec!["readme.txt", "docs/x.js"]);
	assert!(!listing.encrypted);
	assert!(!listing.too_many);
}

#[test]
fn an_encrypted_entry_marks_the_archive_encrypted() {
	let listing = list_zip(&corpus::zip(&[
		ZipEntry {
			name: "a.txt",
			encrypted: false,
		},
		ZipEntry {
			name: "b.pdf",
			encrypted: true,
		},
	]));
	assert_eq!(listing.names.len(), 2);
	assert!(listing.encrypted);
}

#[test]
fn traditional_strong_and_aes_encryption_all_count() {
	assert!(is_encrypted(0x0001, 8));
	assert!(is_encrypted(0x0040, 8));
	assert!(is_encrypted(0, 99));
	assert!(!is_encrypted(0x0008, 8));
}

#[test]
fn listing_stops_at_the_entry_cap() {
	let names: Vec<String> = (0..MAX_ENTRIES + 5).map(|i| format!("{i}.txt")).collect();
	let names: Vec<&str> = names.iter().map(String::as_str).collect();
	let listing = list_zip(&corpus::zip_of(&names));
	assert_eq!(listing.names.len(), MAX_ENTRIES);
	assert!(listing.too_many);
}

#[test]
fn a_zip_without_its_end_record_is_listed_from_local_headers() {
	let mut zip = corpus::zip_of(&["one.txt", "two.vbs"]);
	let end = zip
		.windows(4)
		.position(|window| window == b"PK\x01\x02")
		.expect("central directory present");
	zip.truncate(end);
	let listing = list_zip(&zip);
	assert_eq!(listing.names, vec!["one.txt", "two.vbs"]);
}

#[test]
fn ooxml_is_recognised_and_its_vba_project_found() {
	let docm = list_zip(&corpus::zip_of(&[
		"[Content_Types].xml",
		"word/document.xml",
		"word/vbaProject.bin",
	]));
	assert!(is_ooxml(&docm));
	assert!(ooxml_has_macros(&docm));
	let docx = list_zip(&corpus::zip_of(&[
		"[Content_Types].xml",
		"word/document.xml",
	]));
	assert!(is_ooxml(&docx));
	assert!(!ooxml_has_macros(&docx));
	assert!(!is_ooxml(&list_zip(&corpus::zip_of(&["a.txt"]))));
}

#[test]
fn ole2_macros_are_found_only_in_a_directory_entry() {
	assert!(ole2_has_macros(&corpus::ole2("_VBA_PROJECT")));
	assert!(ole2_has_macros(&corpus::ole2("_VBA_PROJECT_CUR")));
	assert!(!ole2_has_macros(&corpus::ole2("WordDocument")));
	// The same UTF-16 text inside a stream, off the entry grid, is document
	// text and not a macro storage.
	let mut text = corpus::ole2("WordDocument");
	let name: Vec<u8> = "_VBA_PROJECT"
		.encode_utf16()
		.flat_map(u16::to_le_bytes)
		.collect();
	text[700..700 + name.len()].copy_from_slice(&name);
	assert!(!ole2_has_macros(&text));
	// On the grid but followed by more text where an entry records its name
	// length: still text.
	let mut aligned = corpus::ole2("WordDocument");
	let sentence: Vec<u8> = "_VBA_PROJECT is mentioned in this sentence of the body"
		.encode_utf16()
		.flat_map(u16::to_le_bytes)
		.collect();
	aligned[640..640 + sentence.len()].copy_from_slice(&sentence);
	assert!(!ole2_has_macros(&aligned));
}
