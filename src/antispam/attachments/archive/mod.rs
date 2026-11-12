//! Entry names of a zip archive, read from its directory records without
//! decompressing or extracting anything, and whether any entry is
//! encrypted. Office macros are detected here too, since an OOXML document
//! is a zip and an OLE2 file keeps its macro storage in its directory.
//!
//! This does not try to reproduce every extractor. The names of every
//! source (central directories, local headers, Unicode Path fields) are
//! listed and judged, but only a simple, consistent zip comes out clean:
//! any disagreement between sources makes the archive
//! [`Listing::ambiguous`], and anything this reader cannot follow makes it
//! [`Listing::unreadable`]. The end record is searched for only in the last
//! 65,557 bytes, and the records read from all sources are capped.

/// Most entries listed from one archive. An archive with more is reported
/// as [`Listing::too_many`] and judged on the entries read so far.
pub const MAX_ENTRIES: usize = 1000;

/// Longest entry name kept, in bytes. A longer name keeps its head and
/// its last [`NAME_TAIL_BYTES`], so the extension survives the cut.
const MAX_NAME_BYTES: usize = 1024;

/// Bytes kept from the end of a name that is cut.
const NAME_TAIL_BYTES: usize = 255;

/// End of central directory record: signature plus fixed fields.
const EOCD_LEN: usize = 22;
/// The archive comment that may follow the end record is at most this long.
const MAX_COMMENT: usize = 0xffff;

/// Compression methods common extractors handle: stored, deflate,
/// deflate64, bzip2, LZMA, zstd, xz, PPMd and AES (99).
const KNOWN_METHODS: &[u16] = &[0, 8, 9, 12, 14, 93, 95, 98, 99];

const CENTRAL: &[u8] = b"PK\x01\x02";
const LOCAL: &[u8] = b"PK\x03\x04";

/// End of central directory records read, last first. More than this is
/// ambiguous on its own.
const MAX_END_RECORDS: usize = 4;

/// Records read from all sources together (each directory and the local
/// headers). Past this the listing is a scan-limit.
pub const MAX_RECORDS: usize = 10_000;

/// The Info-ZIP Unicode Path extra field: some extractors show this name
/// instead of the one in the header.
const UNICODE_PATH: u16 = 0x7075;

/// Bit 11 says the name is UTF-8.
const EFS: u16 = 0x0800;

/// What the directory of a zip says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
	/// Entry names from every source, lossily decoded as UTF-8.
	pub names: Vec<String>,
	/// At least one entry is encrypted (traditional, strong or AES).
	pub encrypted: bool,
	/// More than [`MAX_ENTRIES`] names, or more than [`MAX_RECORDS`]
	/// records across all sources.
	pub too_many: bool,
	/// Something could not be read: no end record, a directory that ends
	/// early, an unknown compression method.
	pub unreadable: bool,
	/// The archive is not one simple, consistent zip, so extractors can
	/// unpack different files from it: more than one end record, data in
	/// front of the first local header or an offset that does not match,
	/// central and local records that differ, entries only the local
	/// headers list, a Unicode Path field, a name that is not the UTF-8 it
	/// claims, or encryption on some files only.
	pub ambiguous: bool,
}

/// The listing being built, with the bookkeeping that bounds it.
struct Builder {
	listing: Listing,
	seen: std::collections::HashSet<String>,
	records: usize,
	encrypted_files: usize,
	plain_files: usize,
	/// What the central directories say about the entry whose local header
	/// sits at each offset: where data behind a data descriptor ends.
	described: std::collections::HashMap<usize, Described>,
}

/// An entry's method, CRC and sizes as a central directory records them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Described {
	method: u16,
	crc: u32,
	compressed: u32,
	uncompressed: u32,
}

impl Builder {
	fn add(&mut self, name: String) {
		if self.seen.contains(&name) {
			return;
		}
		if self.listing.names.len() == MAX_ENTRIES {
			self.listing.too_many = true;
			return;
		}
		self.seen.insert(name.clone());
		self.listing.names.push(name);
	}

	/// Count one record read; false once the budget is spent.
	fn record(&mut self) -> bool {
		self.records += 1;
		if self.records > MAX_RECORDS {
			self.listing.too_many = true;
		}
		!self.listing.too_many
	}

	fn tally(&mut self, name: &str, encrypted: bool) {
		if name.ends_with('/') {
			return;
		}
		if encrypted {
			self.encrypted_files += 1;
		} else {
			self.plain_files += 1;
		}
	}
}

/// Whether `bytes` ends like a zip, with an end of central directory
/// record in its tail, wherever the archive starts.
pub fn has_end_record(bytes: &[u8]) -> bool {
	!end_records(bytes).is_empty()
}

/// List `zip` from its central directories and its local headers. Only a
/// simple, consistent zip comes out neither ambiguous nor unreadable; the
/// names of every source are listed either way.
pub fn list_zip(zip: &[u8]) -> Listing {
	let mut build = Builder {
		listing: Listing::default(),
		seen: Default::default(),
		records: 0,
		encrypted_files: 0,
		plain_files: 0,
		described: Default::default(),
	};
	let records = end_records(zip);
	build.listing.ambiguous |= records.len() > 1;
	let directories: Vec<Directory> = records
		.iter()
		.take(MAX_END_RECORDS)
		.filter_map(|&eocd| directory_from(zip, eocd))
		.collect();
	if directories.is_empty() {
		build.listing.unreadable = true;
	}
	for directory in &directories {
		build.listing.ambiguous |= directory.shift != 0;
		read_directory(zip, directory, &mut build);
	}
	// The local headers, in file order, as streaming extractors read them.
	// Anything in front of the first one is data a zip does not carry.
	let first = zip
		.windows(4)
		.take(MAX_COMMENT)
		.position(|window| window == LOCAL);
	build.listing.ambiguous |= first.is_some_and(|at| at != 0);
	// A directory with no local header in the window means data in front
	// larger than the window: not a simple zip.
	build.listing.ambiguous |= first.is_none() && !directories.is_empty();
	let mut at = first.unwrap_or(zip.len());
	while let Some(local) = local_entry(zip, at) {
		if !build.record() {
			break;
		}
		build.listing.ambiguous |= local.ambiguous;
		for name in &local.names {
			if !build.seen.contains(name) {
				build.listing.ambiguous = true;
				build.tally(name, local.encrypted);
				build.listing.encrypted |= local.encrypted;
				build.add(name.clone());
			}
		}
		let next = match local.data {
			Some((start, size)) => start.checked_add(size),
			// A data descriptor leaves the size to the central directory.
			// ZIP64 sizes, or a descriptor that does not match it, hide
			// where the next header is.
			None => match descriptor_end(zip, at, &local, &build.described) {
				Some(next) => Some(next),
				None => {
					build.listing.ambiguous = true;
					break;
				}
			},
		};
		match next {
			Some(next) if next > at => at = next,
			_ => break,
		}
	}
	build.listing.ambiguous |= build.encrypted_files > 0 && build.plain_files > 0;
	build.listing
}

/// Read one central directory and the local header of each entry.
fn read_directory(zip: &[u8], directory: &Directory, build: &mut Builder) {
	let mut at = directory.start;
	let mut read = 0u64;
	while read < directory.entries {
		if !build.record() {
			return;
		}
		let Some(entry) = central_entry(zip, at) else {
			build.listing.unreadable = true;
			return;
		};
		read += 1;
		build.tally(&entry.names[0], entry.encrypted);
		build.listing.encrypted |= entry.encrypted;
		build.listing.unreadable |= !KNOWN_METHODS.contains(&entry.method);
		build.listing.ambiguous |= entry.ambiguous;
		let local_at = entry
			.local_offset
			.and_then(|offset| offset.checked_add(directory.shift));
		if let (Some(local_at), Some(sizes)) = (local_at, entry.sizes) {
			build.described.entry(local_at).or_insert(sizes);
		}
		match local_at.and_then(|offset| local_entry(zip, offset)) {
			Some(local) => {
				build.listing.ambiguous |= local.names != entry.names
					|| local.ambiguous
					|| local.encrypted != entry.encrypted;
				build.listing.unreadable |= local.method != entry.method;
				for name in local.names {
					build.add(name);
				}
			}
			None => {
				// No local header where the directory says: the offsets do
				// not describe this file, so extractors will disagree.
				build.listing.unreadable = true;
				build.listing.ambiguous = true;
			}
		}
		for name in entry.names {
			build.add(name);
		}
		at = entry.next;
	}
}

/// Where a central directory starts, how many entries it declares and
/// how far data before the archive shifted the offsets.
struct Directory {
	start: usize,
	entries: u64,
	shift: usize,
}

/// End records in the last 22 + 65,535 bytes, last first, one more than
/// [`MAX_END_RECORDS`] at most so the caller can tell there were too many.
fn end_records(zip: &[u8]) -> Vec<usize> {
	let lowest = zip.len().saturating_sub(EOCD_LEN + MAX_COMMENT);
	let Some(last) = zip.len().checked_sub(EOCD_LEN) else {
		return Vec::new();
	};
	(lowest..=last)
		.rev()
		.filter(|&at| zip[at..].starts_with(b"PK\x05\x06"))
		.take(MAX_END_RECORDS + 1)
		.collect()
}

/// The directory an end record describes, placed where its size says it
/// ends; data in front shows as a shift between that and its offset.
fn directory_from(zip: &[u8], eocd: usize) -> Option<Directory> {
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
	/// The header name, then the Unicode Path when there is one.
	names: Vec<String>,
	/// A Unicode Path is present, or the name is not the UTF-8 it claims.
	ambiguous: bool,
	encrypted: bool,
	method: u16,
	/// Central records: where the local header is, when it can be read.
	local_offset: Option<usize>,
	/// Central records: where the next record starts.
	next: usize,
	/// Local records: where the compressed data starts and its size, when
	/// the header records it (no data descriptor, no ZIP64 size).
	data: Option<(usize, usize)>,
	/// Local records: bit 3, the sizes follow the data in a descriptor.
	descriptor: bool,
	/// Central records: the method, CRC and sizes they record.
	sizes: Option<Described>,
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
		descriptor: false,
		sizes: Some(Described {
			method,
			crc: u32_at(zip, at + 16)?,
			compressed: u32_at(zip, at + 20)?,
			uncompressed: u32_at(zip, at + 24)?,
		}),
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

mod local;
mod names;
mod ole;
use local::*;
use names::*;
pub use ole::{Ole, inspect_ole2, is_ooxml, ole2_has_macros, ooxml_has_macros};

#[cfg(test)]
pub(crate) mod tests;
