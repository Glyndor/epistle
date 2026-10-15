//! Entry names of a zip archive, read from its directory records without
//! decompressing or extracting anything, and whether any entry is
//! encrypted. Office macros are detected here too, since an OOXML document
//! is a zip and an OLE2 file keeps its macro storage in its directory.

/// Most entries listed from one archive. An archive with more is reported
/// as [`Listing::too_many`] and judged on the entries read so far.
pub const MAX_ENTRIES: usize = 1000;

/// Longest entry name kept, in bytes; the rest of a longer name is cut.
const MAX_NAME_BYTES: usize = 1024;

/// End of central directory record: signature plus fixed fields.
const EOCD_LEN: usize = 22;
/// The archive comment that may follow the end record is at most this long.
const MAX_COMMENT: usize = 0xffff;

/// What the directory of a zip says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
	/// Entry names, lossily decoded as UTF-8.
	pub names: Vec<String>,
	/// At least one entry is encrypted (traditional or AES).
	pub encrypted: bool,
	/// The archive has more than [`MAX_ENTRIES`] entries.
	pub too_many: bool,
}

/// List `zip` from its central directory, or from its local headers when
/// the end record is missing (a truncated or doctored archive).
pub fn list_zip(zip: &[u8]) -> Listing {
	match central_directory(zip) {
		Some(start) => walk_records(zip, start, b"PK\x01\x02", central_entry),
		None => walk_records(zip, 0, b"PK\x03\x04", local_entry),
	}
}

/// One directory record: its name, whether it is encrypted, and where the
/// next record starts. `None` when the record does not fit `zip`.
type Entry = Option<(String, bool, usize)>;

fn walk_records(
	zip: &[u8],
	mut at: usize,
	signature: &[u8],
	read: fn(&[u8], usize) -> Entry,
) -> Listing {
	let mut listing = Listing::default();
	while zip.get(at..at + 4) == Some(signature) {
		if listing.names.len() == MAX_ENTRIES {
			listing.too_many = true;
			break;
		}
		let Some((name, encrypted, next)) = read(zip, at) else {
			break;
		};
		listing.encrypted |= encrypted;
		listing.names.push(name);
		if next <= at {
			break;
		}
		at = next;
	}
	listing
}

/// The offset of the first central directory record, from the end record.
fn central_directory(zip: &[u8]) -> Option<usize> {
	let lowest = zip.len().saturating_sub(EOCD_LEN + MAX_COMMENT);
	let last = zip.len().checked_sub(EOCD_LEN)?;
	let eocd = (lowest..=last)
		.rev()
		.find(|&at| zip[at..].starts_with(b"PK\x05\x06"))?;
	let start = u32_at(zip, eocd + 16)? as usize;
	(start < eocd).then_some(start)
}

fn central_entry(zip: &[u8], at: usize) -> Entry {
	let flags = u16_at(zip, at + 8)?;
	let method = u16_at(zip, at + 10)?;
	let name_len = u16_at(zip, at + 28)? as usize;
	let extra_len = u16_at(zip, at + 30)? as usize;
	let comment_len = u16_at(zip, at + 32)? as usize;
	let name = name_at(zip, at + 46, name_len)?;
	let next = at + 46 + name_len + extra_len + comment_len;
	Some((name, is_encrypted(flags, method), next))
}

fn local_entry(zip: &[u8], at: usize) -> Entry {
	let flags = u16_at(zip, at + 6)?;
	let method = u16_at(zip, at + 8)?;
	let compressed = u32_at(zip, at + 18)? as usize;
	let name_len = u16_at(zip, at + 26)? as usize;
	let extra_len = u16_at(zip, at + 28)? as usize;
	let name = name_at(zip, at + 30, name_len)?;
	// With a data descriptor (bit 3) the size is not in this header, so the
	// next record cannot be found without inflating; stop after this one.
	let next = if flags & 0x0008 != 0 {
		at
	} else {
		at + 30 + name_len + extra_len + compressed
	};
	Some((name, is_encrypted(flags, method), next))
}

/// Bit 0 marks traditional encryption, bit 6 strong encryption, and
/// method 99 is WinZip AES.
fn is_encrypted(flags: u16, method: u16) -> bool {
	flags & 0x0001 != 0 || flags & 0x0040 != 0 || method == 99
}

fn name_at(zip: &[u8], at: usize, len: usize) -> Option<String> {
	let bytes = zip.get(at..at + len)?;
	let bytes = &bytes[..bytes.len().min(MAX_NAME_BYTES)];
	Some(String::from_utf8_lossy(bytes).into_owned())
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
	Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
	Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

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

/// An OLE2 compound file with a `_VBA_PROJECT` directory entry: Word and
/// Excel keep their macros under it. Directory entries are 128 bytes long
/// and sector aligned, so only those offsets are read, and an entry counts
/// only when its recorded name length matches, which keeps document text
/// that happens to contain the word from matching.
pub fn ole2_has_macros(ole: &[u8]) -> bool {
	const NAME: &[u8] = b"_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0";
	let mut at = 512;
	while at + 128 <= ole.len() {
		if ole[at..].starts_with(NAME)
			&& matches!(u16_at(ole, at + 64), Some(len) if len == 26 || len == 34)
		{
			return true;
		}
		at += 128;
	}
	false
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
