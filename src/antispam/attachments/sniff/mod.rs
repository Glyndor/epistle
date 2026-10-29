//! What an attachment really is, read from the first bytes of its decoded
//! content and never from its name or its declared type.
//!
//! The table is deliberately small: it covers the formats that carry code
//! (PE, ELF, Mach-O, LNK, script shebangs), the containers used to smuggle
//! it past a filter (zip, RAR, 7z, ISO 9660), the Office formats that carry
//! macros (OOXML, OLE2), HTML pages and the image and PDF formats a
//! disguised file usually claims to be.

/// Bytes [`sniff`] reads at most. ISO 9660 keeps its signature at 32769.
pub const SNIFF_WINDOW: usize = 0x8001 + 5;

/// How much of a file is read to tell HTML and SVG apart.
const MARKUP_HEAD: usize = 128 * 1024;

/// How far into a file the `%PDF-` marker may sit; readers accept leading
/// junk, so a PDF that starts with a few bytes of padding is still a PDF.
const PDF_SEARCH: usize = 1024;

/// The format the content's magic bytes identify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealType {
	/// Windows PE (or DOS) executable, `MZ`.
	Pe,
	/// ELF executable or shared object.
	Elf,
	/// Mach-O executable, thin or fat.
	MachO,
	/// Windows shell link (`.lnk`).
	Lnk,
	/// A script that names its interpreter with `#!`.
	Script,
	/// A zip archive that is not an Office document.
	Zip,
	/// An Office Open XML document (a zip with `[Content_Types].xml`).
	Ooxml,
	/// An OLE2 compound file (legacy Office, MSI).
	Ole2,
	/// A PDF document.
	Pdf,
	/// A PNG image.
	Png,
	/// A JPEG image.
	Jpeg,
	/// A GIF image.
	Gif,
	/// A WebP image.
	Webp,
	/// A BMP image.
	Bmp,
	/// A TIFF image.
	Tiff,
	/// A Windows icon.
	Ico,
	/// A HEIF image (HEIC, AVIF).
	Heif,
	/// An SVG image, which is XML and may carry script. Not a raster image:
	/// a raster claim on SVG bytes is a type mismatch.
	Svg,
	/// A RAR archive.
	Rar,
	/// A 7z archive.
	SevenZip,
	/// An ISO 9660 disk image.
	Iso,
	/// An HTML page.
	Html,
	/// Nothing in the table matched.
	Unknown,
}

impl RealType {
	/// The stable name printed by `epistle attachments check`.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pe => "pe",
			Self::Elf => "elf",
			Self::MachO => "mach-o",
			Self::Lnk => "lnk",
			Self::Script => "script",
			Self::Zip => "zip",
			Self::Ooxml => "ooxml",
			Self::Ole2 => "ole2",
			Self::Pdf => "pdf",
			Self::Png => "png",
			Self::Jpeg => "jpeg",
			Self::Gif => "gif",
			Self::Webp => "webp",
			Self::Bmp => "bmp",
			Self::Tiff => "tiff",
			Self::Ico => "ico",
			Self::Heif => "heif",
			Self::Svg => "svg",
			Self::Rar => "rar",
			Self::SevenZip => "7z",
			Self::Iso => "iso9660",
			Self::Html => "html",
			Self::Unknown => "unknown",
		}
	}

	/// Formats that run code when opened, whatever the file is called.
	pub fn is_executable(self) -> bool {
		matches!(
			self,
			Self::Pe | Self::Elf | Self::MachO | Self::Lnk | Self::Script
		)
	}

	/// The raster image formats in the table.
	pub fn is_image(self) -> bool {
		matches!(
			self,
			Self::Png
				| Self::Jpeg | Self::Gif
				| Self::Webp | Self::Bmp
				| Self::Tiff | Self::Ico
				| Self::Heif
		)
	}

	/// A binary format no text body starts with: everything in the table
	/// except HTML, SVG and scripts, which are text themselves.
	pub fn is_binary(self) -> bool {
		!matches!(self, Self::Unknown | Self::Html | Self::Script | Self::Svg)
	}
}

/// Identify `content` from its leading bytes. `content` may be the whole
/// file or only its first [`SNIFF_WINDOW`] bytes. A zip is reported as
/// [`RealType::Ooxml`] only by the caller, which has the entry list.
pub fn sniff(content: &[u8]) -> RealType {
	const TABLE: &[(&[u8], RealType)] = &[
		(b"MZ", RealType::Pe),
		(b"\x7fELF", RealType::Elf),
		(b"\xfe\xed\xfa\xce", RealType::MachO),
		(b"\xfe\xed\xfa\xcf", RealType::MachO),
		(b"\xce\xfa\xed\xfe", RealType::MachO),
		(b"\xcf\xfa\xed\xfe", RealType::MachO),
		(b"\xca\xfe\xba\xbe", RealType::MachO),
		(
			b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46",
			RealType::Lnk,
		),
		(b"#!", RealType::Script),
		(b"PK\x03\x04", RealType::Zip),
		(b"PK\x05\x06", RealType::Zip),
		(b"PK\x07\x08", RealType::Zip),
		(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", RealType::Ole2),
		(b"\x89PNG\r\n\x1a\n", RealType::Png),
		(b"\xff\xd8\xff", RealType::Jpeg),
		(b"GIF87a", RealType::Gif),
		(b"GIF89a", RealType::Gif),
		(b"II*\x00", RealType::Tiff),
		(b"MM\x00*", RealType::Tiff),
		(b"Rar!\x1a\x07", RealType::Rar),
		(b"7z\xbc\xaf\x27\x1c", RealType::SevenZip),
	];
	for (magic, kind) in TABLE {
		if content.starts_with(magic) {
			return *kind;
		}
	}
	if content.len() >= 12 && &content[..4] == b"RIFF" && &content[8..12] == b"WEBP" {
		return RealType::Webp;
	}
	// BMP and ICO signatures are short, so their reserved zero fields are
	// checked too, which keeps a text starting with "BM" from matching.
	if content.len() >= 14 && content.starts_with(b"BM") && content[6..10] == [0; 4] {
		return RealType::Bmp;
	}
	if content.len() >= 6 && content.starts_with(b"\x00\x00\x01\x00") && content[4..6] != [0, 0] {
		return RealType::Ico;
	}
	if content.len() >= 12
		&& &content[4..8] == b"ftyp"
		&& [
			&b"heic"[..],
			b"heix",
			b"hevc",
			b"mif1",
			b"msf1",
			b"avif",
			b"avis",
		]
		.contains(&&content[8..12])
	{
		return RealType::Heif;
	}
	let head = &content[..content.len().min(PDF_SEARCH)];
	if head.windows(5).any(|window| window == b"%PDF-") {
		return RealType::Pdf;
	}
	if [0x8001usize, 0x8801, 0x9001]
		.iter()
		.any(|&offset| content.get(offset..offset + 5) == Some(b"CD001"))
	{
		return RealType::Iso;
	}
	// Markup is read through UTF-16 and past prologs, doctypes and
	// comments, and HTML is decided first: a page with an inline SVG is
	// still a page.
	let head = super::svg::text_view(&content[..content.len().min(MARKUP_HEAD)]);
	if looks_like_html(&head) {
		return RealType::Html;
	}
	if super::svg::is_svg(&head) {
		return RealType::Svg;
	}
	RealType::Unknown
}

/// An HTML page: after an optional byte-order mark and whitespace, one of
/// the tags a page starts with. Case does not matter to browsers.
fn looks_like_html(content: &[u8]) -> bool {
	const OPENERS: &[&[u8]] = &[
		b"<!doctype html",
		b"<html",
		b"<head",
		b"<body",
		b"<script",
		b"<iframe",
		b"<form",
		b"<meta",
	];
	let content = content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content);
	let start = content
		.iter()
		.take(1024)
		.position(|byte| !byte.is_ascii_whitespace())
		.unwrap_or(content.len());
	let rest = &content[start..];
	const ROOTS: &[&str] = &["html", "head", "body", "script", "iframe", "form", "meta"];
	OPENERS.iter().any(|opener| {
		rest.len() >= opener.len() && rest[..opener.len()].eq_ignore_ascii_case(opener)
	}) || super::svg::root_element(content).is_some_and(|root| ROOTS.contains(&root.as_str()))
}

#[cfg(test)]
mod tests;
