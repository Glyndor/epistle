//! OOXML and OLE2 macro detection.

use super::*;

/// An OOXML document carries its VBA project as `vbaProject.bin`.
pub fn ooxml_has_macros(listing: &Listing) -> bool {
	listing.names.iter().any(|name| {
		let name = name.to_ascii_lowercase();
		name == "vbaproject.bin" || name.ends_with("/vbaproject.bin")
	})
}

/// An OOXML document is a zip that declares its parts in
/// `[Content_Types].xml`.
pub fn is_ooxml(listing: &Listing) -> bool {
	listing
		.names
		.iter()
		.any(|name| name.eq_ignore_ascii_case("[Content_Types].xml"))
}

/// What the directory of an OLE2 compound file shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ole {
	/// A `_VBA_PROJECT` entry: Word and Excel keep their macros under it.
	pub macros: bool,
	/// An `EncryptedPackage` entry: a password-protected Office document,
	/// which no scanner can read.
	pub encrypted: bool,
	/// The file is not a whole number of 512-byte sectors, so it was cut
	/// or built by hand and its directory cannot be trusted.
	pub unreadable: bool,
}

/// Read the directory entries of an OLE2 file. Entries are 128 bytes long
/// and sector aligned, so only those offsets are read, and an entry counts
/// only when its recorded name length matches, which keeps document text
/// that happens to contain the word from matching.
pub fn inspect_ole2(ole: &[u8]) -> Ole {
	let mut found = Ole {
		unreadable: ole.len() < 1024 || !ole.len().is_multiple_of(512),
		..Ole::default()
	};
	let mut at = 512;
	while at + 128 <= ole.len() {
		let entry = &ole[at..at + 128];
		let len = u16_at(entry, 64);
		found.macros |=
			utf16_name(entry, "_VBA_PROJECT", len) || utf16_name(entry, "_VBA_PROJECT_CUR", len);
		found.encrypted |= utf16_name(entry, "EncryptedPackage", len);
		at += 128;
	}
	found
}

/// Whether a directory entry is named `name`: UTF-16LE with the recorded
/// length, terminator included.
fn utf16_name(entry: &[u8], name: &str, recorded: Option<u16>) -> bool {
	let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
	entry.starts_with(&encoded) && recorded == u16::try_from(encoded.len() + 2).ok()
}

/// An OLE2 compound file with a VBA project. See [`inspect_ole2`].
pub fn ole2_has_macros(ole: &[u8]) -> bool {
	inspect_ole2(ole).macros
}
