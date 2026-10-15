//! Entry names of a zip archive, read from its directory records without
//! decompressing or extracting anything, and whether any entry is
//! encrypted. Office macros are detected here too, since an OOXML document
//! is a zip and an OLE2 file keeps its macro storage in its directory.
//!
//! Extractors disagree on which records they trust: most read the central
//! directory, streaming ones read the local headers. Both are read, every
//! name from either counts, and any disagreement between them, or anything
//! this reader cannot follow, makes the archive [`Listing::unreadable`]
//! rather than clean.

/// Most entries listed from one archive. An archive with more is reported
/// as [`Listing::too_many`] and judged on the entries read so far.
pub const MAX_ENTRIES: usize = 1000;

/// Longest entry name kept, in bytes; the rest of a longer name is cut.
const MAX_NAME_BYTES: usize = 1024;

/// End of central directory record: signature plus fixed fields.
const EOCD_LEN: usize = 22;
/// The archive comment that may follow the end record is at most this long.
const MAX_COMMENT: usize = 0xffff;

/// Compression methods common extractors handle: stored, deflate,
/// deflate64, bzip2, LZMA, zstd, xz, PPMd and AES (99).
const KNOWN_METHODS: &[u16] = &[0, 8, 9, 12, 14, 93, 95, 98, 99];

const CENTRAL: &[u8] = b"PK\x01\x02";
const LOCAL: &[u8] = b"PK\x03\x04";

/// What the directory of a zip says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
	/// Entry names from both directories, lossily decoded as UTF-8.
	pub names: Vec<String>,
	/// At least one entry is encrypted (traditional, strong or AES).
	pub encrypted: bool,
	/// The archive has more than [`MAX_ENTRIES`] entries.
	pub too_many: bool,
	/// Something in the archive could not be read completely or reads two
	/// ways: a missing or inconsistent directory, data before the archive,
	/// an unknown compression method, encryption on some files only.
	pub unreadable: bool,
}

impl Listing {
	fn add(&mut self, name: String) {
		if self.names.len() == MAX_ENTRIES {
			self.too_many = true;
		} else if !self.names.contains(&name) {
			self.names.push(name);
		}
	}
}

/// Whether `bytes` ends like a zip, with an end of central directory
/// record in its tail, wherever the archive starts.
pub fn has_end_record(bytes: &[u8]) -> bool {
	end_record(bytes).is_some()
}

/// List `zip` from its central directory and its local headers.
pub fn list_zip(zip: &[u8]) -> Listing {
	let mut listing = Listing::default();
	let mut encrypted_files = 0usize;
	let mut plain_files = 0usize;
	let mut tally = |name: &str, encrypted: bool| {
		if !name.ends_with('/') {
			if encrypted {
				encrypted_files += 1;
			} else {
				plain_files += 1;
			}
		}
	};
	match central_directory(zip) {
		Some(directory) => {
			// Data before the archive moves every offset; extractors cope,
			// and polyglot files rely on it.
			listing.unreadable |= directory.shift != 0;
			let mut at = directory.start;
			let mut read = 0u64;
			while read < directory.entries && !listing.too_many {
				let Some(entry) = central_entry(zip, at) else {
					listing.unreadable = true;
					break;
				};
				read += 1;
				tally(&entry.name, entry.encrypted);
				listing.encrypted |= entry.encrypted;
				listing.unreadable |= !KNOWN_METHODS.contains(&entry.method);
				match entry
					.local_offset
					.and_then(|offset| offset.checked_add(directory.shift))
					.and_then(|offset| local_entry(zip, offset))
				{
					Some(local) => {
						listing.unreadable |= local.name != entry.name
							|| local.encrypted != entry.encrypted
							|| local.method != entry.method;
						listing.add(local.name);
					}
					None => listing.unreadable = true,
				}
				listing.add(entry.name);
				at = entry.next;
			}
		}
		None => listing.unreadable = true,
	}
	// Streaming extractors read the local headers in file order: a file
	// the central directory does not list still comes out of them.
	let mut at = zip
		.windows(4)
		.take(MAX_COMMENT)
		.position(|window| window == LOCAL)
		.unwrap_or(zip.len());
	let mut steps = 0;
	while steps < MAX_ENTRIES
		&& let Some(local) = local_entry(zip, at)
	{
		steps += 1;
		let next = local.next(zip);
		if !listing.names.contains(&local.name) {
			listing.unreadable = true;
			tally(&local.name, local.encrypted);
			listing.encrypted |= local.encrypted;
			listing.add(local.name);
		}
		let Some(next) = next else {
			break;
		};
		at = next;
	}
	listing.unreadable |= encrypted_files > 0 && plain_files > 0;
	listing
}

/// Where the central directory starts, how many entries it declares and
/// how far data before the archive shifted the offsets.
struct Directory {
	start: usize,
	entries: u64,
	shift: usize,
}

fn end_record(zip: &[u8]) -> Option<usize> {
	let lowest = zip.len().saturating_sub(EOCD_LEN + MAX_COMMENT);
	let last = zip.len().checked_sub(EOCD_LEN)?;
	(lowest..=last)
		.rev()
		.find(|&at| zip[at..].starts_with(b"PK\x05\x06"))
}

fn central_directory(zip: &[u8]) -> Option<Directory> {
	let eocd = end_record(zip)?;
	let mut entries = u64::from(u16_at(zip, eocd + 10)?);
	let mut size = u64::from(u32_at(zip, eocd + 12)?);
	let mut offset = u64::from(u32_at(zip, eocd + 16)?);
	let mut end = eocd;
	if entries == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff {
		// ZIP64: the locator just before the end record points at the
		// 64-bit end record, which holds the real values.
		let locator = eocd.checked_sub(20)?;
		if !zip[locator..].starts_with(b"PK\x06\x07") {
			return None;
		}
		let record = usize::try_from(u64_at(zip, locator + 8)?).ok()?;
		if !zip.get(record..)?.starts_with(b"PK\x06\x06") {
			return None;
		}
		entries = u64_at(zip, record + 32)?;
		size = u64_at(zip, record + 40)?;
		offset = u64_at(zip, record + 48)?;
		end = record;
	}
	let start = end.checked_sub(usize::try_from(size).ok()?)?;
	let shift = start.checked_sub(usize::try_from(offset).ok()?)?;
	Some(Directory {
		start,
		entries,
		shift,
	})
}

/// One record from either directory.
struct Entry {
	name: String,
	encrypted: bool,
	method: u16,
	/// Central records: where the local header is, when it can be read.
	local_offset: Option<usize>,
	/// Central records: where the next record starts.
	next: usize,
	/// Local records: where the compressed data starts and its size, when
	/// the header records it (no data descriptor).
	data: Option<(usize, usize)>,
	at: usize,
}

impl Entry {
	/// The next local header: right after the data when its size is known,
	/// otherwise the next local signature, as streaming extractors look for.
	fn next(&self, zip: &[u8]) -> Option<usize> {
		match self.data {
			Some((start, size)) => start.checked_add(size),
			None => {
				let from = self.at + 4;
				zip.get(from..)?
					.windows(4)
					.position(|window| window == LOCAL)
					.map(|offset| from + offset)
			}
		}
	}
}

fn central_entry(zip: &[u8], at: usize) -> Option<Entry> {
	if zip.get(at..at + 4)? != CENTRAL {
		return None;
	}
	let flags = u16_at(zip, at + 8)?;
	let method = u16_at(zip, at + 10)?;
	let name_len = usize::from(u16_at(zip, at + 28)?);
	let extra_len = usize::from(u16_at(zip, at + 30)?);
	let comment_len = usize::from(u16_at(zip, at + 32)?);
	let name = name_at(zip, at + 46, name_len)?;
	let mut local_offset = Some(u32_at(zip, at + 42)? as usize);
	if local_offset == Some(0xffff_ffff) {
		let extra = zip.get(at + 46 + name_len..at + 46 + name_len + extra_len)?;
		local_offset = zip64_offset(zip, at, extra);
	}
	Some(Entry {
		name,
		encrypted: is_encrypted(flags, method),
		method,
		local_offset,
		next: at + 46 + name_len + extra_len + comment_len,
		data: None,
		at,
	})
}

/// The local header offset from a ZIP64 extra field (id 1). It follows the
/// 64-bit sizes that the central record also left at `0xffffffff`.
fn zip64_offset(zip: &[u8], at: usize, mut extra: &[u8]) -> Option<usize> {
	let skipped = [u32_at(zip, at + 24)?, u32_at(zip, at + 20)?]
		.iter()
		.filter(|&&size| size == 0xffff_ffff)
		.count();
	while extra.len() >= 4 {
		let id = u16_at(extra, 0)?;
		let len = usize::from(u16_at(extra, 2)?);
		let body = extra.get(4..4 + len)?;
		if id == 1 {
			return usize::try_from(u64_at(body, skipped * 8)?).ok();
		}
		extra = &extra[4 + len..];
	}
	None
}

fn local_entry(zip: &[u8], at: usize) -> Option<Entry> {
	if zip.get(at..at + 4)? != LOCAL {
		return None;
	}
	let flags = u16_at(zip, at + 6)?;
	let method = u16_at(zip, at + 8)?;
	let compressed = u32_at(zip, at + 18)? as usize;
	let name_len = usize::from(u16_at(zip, at + 26)?);
	let extra_len = usize::from(u16_at(zip, at + 28)?);
	let name = name_at(zip, at + 30, name_len)?;
	let start = at + 30 + name_len + extra_len;
	// With a data descriptor (bit 3), or a ZIP64 size, the header does not
	// say where the data ends.
	let data = (flags & 0x0008 == 0 && compressed != 0xffff_ffff).then_some((start, compressed));
	Some(Entry {
		name,
		encrypted: is_encrypted(flags, method),
		method,
		local_offset: None,
		next: start,
		data,
		at,
	})
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

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
	Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
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

#[cfg(test)]
#[path = "archive_tests_damaged.rs"]
mod tests_damaged;
