//! Entry names of a zip archive, read from its directory records without
//! decompressing or extracting anything, and whether any entry is
//! encrypted. Office macros are detected here too, since an OOXML document
//! is a zip and an OLE2 file keeps its macro storage in its directory.
//!
//! Extractors disagree on which records they trust: most read the central
//! directory, streaming ones read the local headers, some take the first
//! end record and some the last, 7-Zip and WinRAR prefer a Unicode Path
//! field. Every source is read and every name from any of them counts; a
//! disagreement makes the archive [`Listing::ambiguous`], and anything this
//! reader cannot follow makes it [`Listing::unreadable`], never clean.

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

/// End of central directory records looked at, last first. Extractors
/// differ on which one they believe; a fake one hidden in the archive
/// comment is the classic case.
const MAX_END_RECORDS: usize = 4;

/// Directory records read from one directory before giving up: repeated
/// names do not grow the listing, so this bounds the work.
const MAX_RECORDS: usize = 4 * MAX_ENTRIES;

/// The Info-ZIP Unicode Path extra field: 7-Zip and WinRAR show this name
/// instead of the one in the header.
const UNICODE_PATH: u16 = 0x7075;

/// Bit 11 says the name is UTF-8.
const EFS: u16 = 0x0800;

/// What the directory of a zip says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
	/// Entry names from every source (each end record's directory, the
	/// local headers, Unicode Path fields, each reading of the bytes).
	pub names: Vec<String>,
	/// At least one entry is encrypted (traditional, strong or AES).
	pub encrypted: bool,
	/// The archive has more than [`MAX_ENTRIES`] entries.
	pub too_many: bool,
	/// Something could not be read: no end record, a directory that ends
	/// early, an unknown compression method, encryption on some files only.
	pub unreadable: bool,
	/// The sources disagree, so two extractors can unpack different files:
	/// several end records, data in front, central and local names that
	/// differ, entries only the local headers list, a Unicode Path that
	/// differs from the name, or a name that is not valid UTF-8 although it
	/// says it is.
	pub ambiguous: bool,
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
	!end_records(bytes).is_empty()
}

/// Counts of encrypted and plain files, directories left out.
#[derive(Default)]
struct Tally {
	encrypted: usize,
	plain: usize,
}

impl Tally {
	fn count(&mut self, name: &str, encrypted: bool) {
		if name.ends_with('/') {
			return;
		}
		if encrypted {
			self.encrypted += 1;
		} else {
			self.plain += 1;
		}
	}
}

/// List `zip` from every directory any extractor may read and from its
/// local headers.
pub fn list_zip(zip: &[u8]) -> Listing {
	let mut listing = Listing::default();
	let mut tally = Tally::default();
	let directories = central_directories(zip);
	if directories.is_empty() {
		listing.unreadable = true;
	}
	if directories.len() > 1 || directories.iter().any(|directory| directory.shift != 0) {
		listing.ambiguous = true;
	}
	for directory in &directories {
		read_directory(zip, directory, &mut listing, &mut tally);
	}
	// Streaming extractors read the local headers in file order: a file
	// no central directory lists still comes out of them.
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
		listing.ambiguous |= local.ambiguous;
		for name in local.names {
			if !listing.names.contains(&name) {
				listing.ambiguous = true;
				tally.count(&name, local.encrypted);
				listing.encrypted |= local.encrypted;
				listing.add(name);
			}
		}
		let Some(next) = next else {
			break;
		};
		at = next;
	}
	listing.unreadable |= tally.encrypted > 0 && tally.plain > 0;
	listing
}

/// Read one central directory and the local header of each entry.
fn read_directory(zip: &[u8], directory: &Directory, listing: &mut Listing, tally: &mut Tally) {
	let mut at = directory.start;
	let mut read = 0u64;
	while read < directory.entries && !listing.too_many {
		if read as usize >= MAX_RECORDS {
			listing.too_many = true;
			break;
		}
		let Some(entry) = central_entry(zip, at) else {
			listing.unreadable = true;
			break;
		};
		read += 1;
		tally.count(&entry.names[0], entry.encrypted);
		listing.encrypted |= entry.encrypted;
		listing.unreadable |= !KNOWN_METHODS.contains(&entry.method);
		listing.ambiguous |= entry.ambiguous;
		match entry
			.local_offset
			.and_then(|offset| offset.checked_add(directory.shift))
			.and_then(|offset| local_entry(zip, offset))
		{
			Some(local) => {
				listing.ambiguous |= local.names != entry.names || local.ambiguous;
				listing.unreadable |=
					local.encrypted != entry.encrypted || local.method != entry.method;
				for name in local.names {
					listing.add(name);
				}
			}
			None => listing.unreadable = true,
		}
		let next = entry.next;
		for name in entry.names {
			listing.add(name);
		}
		at = next;
	}
}

/// Where a central directory starts, how many entries it declares and
/// how far data before the archive shifted the offsets.
#[derive(PartialEq, Eq)]
struct Directory {
	start: usize,
	entries: u64,
	shift: usize,
}

/// End records in the tail, last first, at most [`MAX_END_RECORDS`].
fn end_records(zip: &[u8]) -> Vec<usize> {
	let lowest = zip.len().saturating_sub(EOCD_LEN + MAX_COMMENT);
	let Some(last) = zip.len().checked_sub(EOCD_LEN) else {
		return Vec::new();
	};
	(lowest..=last)
		.rev()
		.filter(|&at| zip[at..].starts_with(b"PK\x05\x06"))
		.take(MAX_END_RECORDS)
		.collect()
}

/// Every directory an extractor may read: from each end record, both
/// where its size says the directory ends (what tolerant extractors use
/// when data sits in front) and where its offset says it starts.
fn central_directories(zip: &[u8]) -> Vec<Directory> {
	let mut directories = Vec::new();
	for eocd in end_records(zip) {
		let Some(found) = directory_from(zip, eocd) else {
			continue;
		};
		for directory in found {
			let plausible = zip.get(directory.start..directory.start + 4) == Some(CENTRAL)
				|| directory.entries == 0;
			if plausible && !directories.contains(&directory) {
				directories.push(directory);
			}
		}
	}
	directories
}

fn directory_from(zip: &[u8], eocd: usize) -> Option<Vec<Directory>> {
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
	let offset = usize::try_from(offset).ok()?;
	let mut found = Vec::new();
	if let Some(shift) = start.checked_sub(offset) {
		found.push(Directory {
			start,
			entries,
			shift,
		});
	}
	if offset != start && offset < end {
		found.push(Directory {
			start: offset,
			entries,
			shift: 0,
		});
	}
	Some(found)
}

/// One record from either directory.
struct Entry {
	/// The header name, each reading of its bytes, then the Unicode Path.
	names: Vec<String>,
	/// The readings disagree, or the name is not the UTF-8 it claims.
	ambiguous: bool,
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
	let raw_name = zip.get(at + 46..at + 46 + name_len)?;
	let extra = zip.get(at + 46 + name_len..at + 46 + name_len + extra_len)?;
	let (names, ambiguous) = names_of(raw_name, flags, extra);
	let mut local_offset = Some(u32_at(zip, at + 42)? as usize);
	if local_offset == Some(0xffff_ffff) {
		local_offset = zip64_offset(zip, at, extra);
	}
	Some(Entry {
		names,
		ambiguous,
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
fn zip64_offset(zip: &[u8], at: usize, extra: &[u8]) -> Option<usize> {
	let skipped = [u32_at(zip, at + 24)?, u32_at(zip, at + 20)?]
		.iter()
		.filter(|&&size| size == 0xffff_ffff)
		.count();
	let body = extra_field(extra, 1)?;
	usize::try_from(u64_at(body, skipped * 8)?).ok()
}

/// The body of the first extra field with this id.
fn extra_field(mut extra: &[u8], wanted: u16) -> Option<&[u8]> {
	while extra.len() >= 4 {
		let id = u16_at(extra, 0)?;
		let len = usize::from(u16_at(extra, 2)?);
		let body = extra.get(4..4 + len)?;
		if id == wanted {
			return Some(body);
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
	let raw_name = zip.get(at + 30..at + 30 + name_len)?;
	let extra = zip.get(at + 30 + name_len..at + 30 + name_len + extra_len)?;
	let (names, ambiguous) = names_of(raw_name, flags, extra);
	let start = at + 30 + name_len + extra_len;
	// With a data descriptor (bit 3), or a ZIP64 size, the header does not
	// say where the data ends.
	let data = (flags & 0x0008 == 0 && compressed != 0xffff_ffff).then_some((start, compressed));
	Some(Entry {
		names,
		ambiguous,
		encrypted: is_encrypted(flags, method),
		method,
		local_offset: None,
		next: start,
		data,
		at,
	})
}

/// Every reading of a name: as UTF-8 (lossy), byte for byte as a legacy
/// code page when it is not ASCII and does not claim UTF-8, and the
/// Unicode Path field when there is one. Ambiguous when the UTF-8 flag is
/// set on bytes that are not UTF-8, or the Unicode Path differs.
fn names_of(raw: &[u8], flags: u16, extra: &[u8]) -> (Vec<String>, bool) {
	let raw = &raw[..raw.len().min(MAX_NAME_BYTES)];
	let mut names = vec![String::from_utf8_lossy(raw).into_owned()];
	let mut ambiguous = flags & EFS != 0 && std::str::from_utf8(raw).is_err();
	if flags & EFS == 0 && !raw.is_ascii() {
		names.push(raw.iter().map(|&byte| char::from(byte)).collect());
	}
	if let Some(body) = extra_field(extra, UNICODE_PATH)
		&& let Some(path) = body.get(5..)
	{
		let path = String::from_utf8_lossy(&path[..path.len().min(MAX_NAME_BYTES)]).into_owned();
		ambiguous |= path != names[0];
		names.push(path);
	}
	names.dedup();
	(names, ambiguous)
}

/// Bit 0 marks traditional encryption, bit 6 strong encryption, and
/// method 99 is WinZip AES.
fn is_encrypted(flags: u16, method: u16) -> bool {
	flags & 0x0001 != 0 || flags & 0x0040 != 0 || method == 99
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

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "archive_tests_damaged.rs"]
mod tests_damaged;

#[cfg(test)]
#[path = "archive_tests_sources.rs"]
pub(crate) mod tests_sources;
