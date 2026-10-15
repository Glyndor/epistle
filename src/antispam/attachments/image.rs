//! Raster images that carry more than a picture: a program, a script or a
//! zip after the image's logical end, or inside its metadata. Each format
//! is walked by its own structure to that end; an image that cannot be
//! walked cleanly is ambiguous, never clean. One bounded pass each.

use super::sniff::RealType;

/// What a raster image hides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImageFacts {
	/// A payload after the logical end or inside a metadata block.
	pub payload: bool,
	/// The structure could not be followed to its logical end.
	pub ambiguous: bool,
}

/// Where an image ends, and the byte ranges of its metadata blocks
/// (comments, text chunks, EXIF, XMP, application extensions).
struct Layout {
	end: usize,
	metadata: Vec<(usize, usize)>,
}

/// Inspect a PNG, JPEG, GIF or WebP. Other types give the default.
pub fn inspect_raster(real: RealType, content: &[u8]) -> ImageFacts {
	let layout = match real {
		RealType::Png => png(content),
		RealType::Jpeg => jpeg(content),
		RealType::Gif => gif(content),
		RealType::Webp => webp(content),
		_ => return ImageFacts::default(),
	};
	let Some(layout) = layout else {
		return ImageFacts {
			payload: false,
			ambiguous: true,
		};
	};
	let tail = content.get(layout.end..).unwrap_or_default();
	let payload = contains_payload(tail)
		|| layout
			.metadata
			.iter()
			.any(|&(start, end)| content.get(start..end).is_some_and(contains_payload));
	ImageFacts {
		payload,
		ambiguous: false,
	}
}

/// PNG chunks, by their lengths, to the end of IEND. A length that runs
/// past the file is a structure that cannot be followed.
fn png(png: &[u8]) -> Option<Layout> {
	const METADATA: &[&[u8]] = &[b"tEXt", b"zTXt", b"iTXt", b"eXIf"];
	let mut metadata = Vec::new();
	let mut at = 8;
	loop {
		let len = u32::from_be_bytes(png.get(at..at + 4)?.try_into().ok()?) as usize;
		let kind = png.get(at + 4..at + 8)?;
		let data = at + 8;
		let next = data.checked_add(len)?.checked_add(4)?;
		if next > png.len() {
			return None;
		}
		if METADATA.contains(&kind) {
			metadata.push((data, data + len));
		}
		if kind == b"IEND" {
			return Some(Layout {
				end: next,
				metadata,
			});
		}
		at = next;
	}
}

/// JPEG segments, by their lengths, up to each start of scan; inside a
/// scan the next marker is a 0xFF not followed by 0x00 or a restart
/// marker. The image ends at the first end-of-image found this way, so an
/// end-of-image inside an APP segment does not count.
fn jpeg(jpeg: &[u8]) -> Option<Layout> {
	let mut metadata = Vec::new();
	let mut at = 2;
	while at + 1 < jpeg.len() {
		if jpeg[at] != 0xff {
			return None;
		}
		let marker = jpeg[at + 1];
		match marker {
			0xd9 => {
				return Some(Layout {
					end: at + 2,
					metadata,
				});
			}
			0xff => at += 1,
			0x01 | 0xd0..=0xd7 => at += 2,
			_ => {
				let len = usize::from(u16::from_be_bytes(
					jpeg.get(at + 2..at + 4)?.try_into().ok()?,
				));
				let next = at.checked_add(2 + len)?;
				if len < 2 || next > jpeg.len() {
					return None;
				}
				if (0xe0..=0xef).contains(&marker) || marker == 0xfe {
					metadata.push((at + 4, next));
				}
				at = next;
				if marker == 0xda {
					while at + 1 < jpeg.len()
						&& !(jpeg[at] == 0xff
							&& jpeg[at + 1] != 0x00
							&& !(0xd0..=0xd7).contains(&jpeg[at + 1]))
					{
						at += 1;
					}
				}
			}
		}
	}
	None
}

/// GIF blocks to the trailer; comment, application and plain-text
/// extensions are metadata.
fn gif(gif: &[u8]) -> Option<Layout> {
	let mut metadata = Vec::new();
	let flags = *gif.get(10)?;
	let mut at = 13;
	if flags & 0x80 != 0 {
		at += 3 << ((flags & 0x07) + 1);
	}
	loop {
		match *gif.get(at)? {
			0x3b => {
				return Some(Layout {
					end: at + 1,
					metadata,
				});
			}
			0x21 => {
				let label = *gif.get(at + 1)?;
				let start = at + 2;
				at = skip_sub_blocks(gif, start)?;
				if matches!(label, 0xfe | 0xff | 0x01) {
					metadata.push((start, at));
				}
			}
			0x2c => {
				let local = *gif.get(at + 9)?;
				at += 10;
				if local & 0x80 != 0 {
					at += 3 << ((local & 0x07) + 1);
				}
				at = skip_sub_blocks(gif, at + 1)?;
			}
			_ => return None,
		}
	}
}

fn skip_sub_blocks(gif: &[u8], mut at: usize) -> Option<usize> {
	loop {
		let size = usize::from(*gif.get(at)?);
		at += 1;
		if size == 0 {
			return Some(at);
		}
		at = at.checked_add(size)?;
		if at > gif.len() {
			return None;
		}
	}
}

/// WebP: the RIFF size must fit the file, and the chunks inside it must
/// add up to it. EXIF and XMP chunks are metadata.
fn webp(webp: &[u8]) -> Option<Layout> {
	let size = u32::from_le_bytes(webp.get(4..8)?.try_into().ok()?) as usize;
	let end = 8usize.checked_add(size)?;
	if size < 4 || end > webp.len() {
		return None;
	}
	let mut metadata = Vec::new();
	let mut at = 12;
	while at < end {
		let kind = webp.get(at..at + 4)?;
		let len = u32::from_le_bytes(webp.get(at + 4..at + 8)?.try_into().ok()?) as usize;
		let data = at + 8;
		let next = data.checked_add(len)?.checked_add(len & 1)?;
		if next > end {
			return None;
		}
		if kind == b"EXIF" || kind == b"XMP " {
			metadata.push((data, data + len));
		}
		at = next;
	}
	Some(Layout { end, metadata })
}

/// A PE (`MZ` whose header offset points at `PE\0\0`), ELF or a zip
/// local header anywhere in `region`, or a `#!/` script at its start
/// (after white space). One pass. A shebang only means something where a
/// file starts, and three bytes turn up by chance in compressed data: a
/// motion photo's video would match about once every 16 MiB.
fn contains_payload(region: &[u8]) -> bool {
	let text = region
		.iter()
		.position(|byte| !byte.is_ascii_whitespace())
		.map_or(&region[region.len()..], |start| &region[start..]);
	text.starts_with(b"#!/")
		|| (0..region.len()).any(|at| {
			let rest = &region[at..];
			rest.starts_with(b"\x7fELF")
				|| rest.starts_with(b"PK\x03\x04")
				|| (rest.starts_with(b"MZ") && is_pe(rest))
		})
}

fn is_pe(mz: &[u8]) -> bool {
	let Some(offset) = mz.get(0x3c..0x40) else {
		return false;
	};
	let offset = u32::from_le_bytes([offset[0], offset[1], offset[2], offset[3]]) as usize;
	mz.get(offset..offset.saturating_add(4)) == Some(b"PE\0\0")
}

#[cfg(test)]
#[path = "image_tests.rs"]
pub(crate) mod tests;
