//! Local file headers and data descriptors of a ZIP archive.

use super::*;

pub(super) fn local_entry(zip: &[u8], at: usize) -> Option<Entry> {
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
	let data = (flags & 0x0008 == 0 && compressed != 0xffff_ffff).then_some((start, compressed));
	Some(Entry {
		names,
		ambiguous,
		encrypted: is_encrypted(flags, method),
		method,
		local_offset: None,
		next: start,
		data,
		descriptor: flags & 0x0008 != 0,
		sizes: None,
	})
}

/// Where the next record starts after a local entry whose sizes are in a
/// data descriptor, read from the central record for the same offset, or
/// `None` when that would not be where every extractor looks. The
/// descriptor must sit right after the data the central record sizes and
/// repeat its CRC and sizes. A local header inside that data is one a
/// streaming extractor could find by trusting where the deflate stream
/// ends. Stored data has no end of its own, so only an empty stored entry
/// with a signed descriptor right after it is followed.
pub(super) fn descriptor_end(
	zip: &[u8],
	at: usize,
	local: &Entry,
	described: &std::collections::HashMap<usize, Described>,
) -> Option<usize> {
	let central = described.get(&at)?;
	if !local.descriptor || central.method != local.method {
		return None;
	}
	let start = local.next;
	let end = start.checked_add(usize::try_from(central.compressed).ok()?)?;
	let data = zip.get(start..end)?;
	if data.windows(LOCAL.len()).any(|window| window == LOCAL) {
		return None;
	}
	let signed = zip.get(end..)?.starts_with(b"PK\x07\x08");
	if central.method == 0 && (central.compressed != 0 || !signed) {
		return None;
	}
	let fields = if signed { end + 4 } else { end };
	let recorded = Described {
		method: central.method,
		crc: u32_at(zip, fields)?,
		compressed: u32_at(zip, fields + 4)?,
		uncompressed: u32_at(zip, fields + 8)?,
	};
	(recorded == *central).then_some(fields + 12)
}
