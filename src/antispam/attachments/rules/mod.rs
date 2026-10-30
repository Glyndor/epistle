//! The rules that judge one attachment: each finding is a [`Reason`] with a
//! stable code, the only thing that ever reaches a header or a log.

use std::collections::BTreeSet;

use super::archive::{Listing, Ole};
use super::sniff::RealType;

/// Extensions Windows (and a few other desktops) run or mount on a double
/// click. Close to the list the large webmail providers refuse.
pub const DANGEROUS_EXTENSIONS: &[&str] = &[
	"ade",
	"adp",
	"apk",
	"app",
	"application",
	"appref-ms",
	"appx",
	"appxbundle",
	"bat",
	"cab",
	"chm",
	"cmd",
	"com",
	"cpl",
	"diagcab",
	"diagcfg",
	"diagpack",
	"dll",
	"dmg",
	"ex_",
	"exe",
	"gadget",
	"hlp",
	"hta",
	"img",
	"inf",
	"ins",
	"iso",
	"isp",
	"jar",
	"jnlp",
	"js",
	"jse",
	"lib",
	"lnk",
	"mde",
	"mjs",
	"msc",
	"msi",
	"msix",
	"msixbundle",
	"msp",
	"mst",
	"nsh",
	"pif",
	"ps1",
	"psc1",
	"psd1",
	"psm1",
	"ps1xml",
	"reg",
	"scf",
	"scr",
	"sct",
	"settingcontent-ms",
	"shb",
	"sys",
	"url",
	"vb",
	"vbe",
	"vbs",
	"vhd",
	"vhdx",
	"vxd",
	"website",
	"ws",
	"wsc",
	"wsf",
	"wsh",
	"xll",
];

/// Extensions a disguised file usually hides behind.
const DECOY_EXTENSIONS: &[&str] = &[
	"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif",
	"zip",
];

/// Image extensions whose formats [`super::sniff`] recognises, so content
/// it does not recognise under one of these names is not that image.
const IMAGE_EXTENSIONS: &[&str] = &[
	"jpg", "jpeg", "jpe", "png", "gif", "webp", "bmp", "tif", "tiff", "ico", "heic", "heif", "avif",
];

/// Declared image types [`super::sniff`] recognises.
const SNIFFABLE_IMAGE_TYPES: &[&str] = &[
	"image/jpeg",
	"image/pjpeg",
	"image/png",
	"image/gif",
	"image/webp",
	"image/bmp",
	"image/tiff",
	"image/x-icon",
	"image/vnd.microsoft.icon",
	"image/heic",
	"image/heif",
	"image/avif",
];

/// Archive formats inside an archive: their content is not listed.
const ARCHIVE_EXTENSIONS: &[&str] = &[
	"zip", "zipx", "rar", "7z", "tar", "gz", "tgz", "bz2", "tbz", "xz", "txz", "z", "lz", "lzh",
	"lha", "arj", "ace", "cab", "iso", "img", "vhd", "vhdx", "dmg", "uue", "xxe",
];

const HTML_EXTENSIONS: &[&str] = &["htm", "html", "shtml", "xht", "xhtml", "mht", "mhtml"];

/// Bidirectional and invisible formatting characters. U+202E (RIGHT-TO-LEFT
/// OVERRIDE) makes `invoice<RLO>gpj.exe` display as `invoiceexe.jpg`; the
/// zero-width ones split an extension so a plain match misses it.
const FORMATTING: &[char] = &[
	'\u{00ad}', '\u{180e}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}',
	'\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}',
	'\u{2064}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{feff}',
];

/// Why an attachment was singled out. The codes are a stable interface:
/// they appear in `X-Epistle-Attachment-Warning` and in command output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
	/// The name ends in an extension that runs or mounts when opened.
	DangerousExtension,
	/// A decoy extension sits before a dangerous one: `factura.pdf.exe`.
	DoubleExtension,
	/// The name carries bidirectional or invisible formatting characters.
	BidiName,
	/// The content is an executable or a script, whatever the name says.
	ExecutableContent,
	/// The content is a disk image (ISO 9660).
	DiskImage,
	/// The name or declared type claims an image or a PDF and the content
	/// is something else.
	TypeMismatch,
	/// An HTML page sent as an attachment, the usual fake login form.
	HtmlAttachment,
	/// An SVG image by any reading: name, declared type or content. SVG can
	/// carry script, and telling script from drawing is never complete.
	ActiveImage,
	/// A raster image with a program, a script or a zip after its end or
	/// inside its metadata.
	AppendedPayload,
	/// An image whose structure cannot be followed to its end, or an SVG
	/// that cannot be read cleanly (entity declarations, broken gzip).
	AmbiguousImage,
	/// An archive holds an entry with a dangerous extension.
	DangerousArchiveEntry,
	/// An archive holds another archive, whose content is not listed.
	NestedArchive,
	/// An archive holds encrypted entries no scanner can read.
	EncryptedArchive,
	/// An archive could not be read completely or reads two ways: RAR and
	/// 7z (never listed), a zip with a missing or inconsistent directory,
	/// data before it, an unknown method, or encryption on some files only.
	UnreadableArchive,
	/// Two extractors would unpack different files from this zip: several
	/// end records, data in front, central and local names that differ,
	/// entries only the local headers list, a Unicode Path field that
	/// differs from the name, a name that is not the UTF-8 it claims.
	AmbiguousArchive,
	/// An Office document carries a VBA project.
	Macro,
	/// Two mail clients could read the MIME structure, a header or an
	/// encoding differently.
	AmbiguousMime,
	/// A cap was hit (depth, parts, header size, decoded bytes, archive
	/// entries or time) and what lay beyond it was not inspected.
	ScanLimit,
}

impl Reason {
	/// The stable code.
	pub fn code(self) -> &'static str {
		match self {
			Self::DangerousExtension => "dangerous-extension",
			Self::DoubleExtension => "double-extension",
			Self::BidiName => "bidi-name",
			Self::ExecutableContent => "executable-content",
			Self::DiskImage => "disk-image",
			Self::TypeMismatch => "type-mismatch",
			Self::HtmlAttachment => "html-attachment",
			Self::ActiveImage => "active-image",
			Self::AppendedPayload => "appended-payload",
			Self::AmbiguousImage => "ambiguous-image",
			Self::DangerousArchiveEntry => "dangerous-archive-entry",
			Self::NestedArchive => "nested-archive",
			Self::EncryptedArchive => "encrypted-archive",
			Self::UnreadableArchive => "unreadable-archive",
			Self::AmbiguousArchive => "ambiguous-archive",
			Self::Macro => "macro",
			Self::AmbiguousMime => "ambiguous-mime",
			Self::ScanLimit => "scan-limit",
		}
	}
}

/// Extensions no `allow_extensions` entry may cover; the configuration
/// refuses them. Each one runs code, installs something or changes the
/// system on a double click, with at most a prompt users learn to accept,
/// and none is a format people need to mail each other.
pub const ALWAYS_DANGEROUS: &[&str] = &[
	// Programs.
	"exe",
	"scr",
	"com",
	"pif",
	"cpl",
	// Command and script hosts: cmd, Windows Script Host (JScript,
	// VBScript, their encoded forms and .wsf/.wsh), PowerShell (scripts,
	// formatting files that can carry script blocks, console files), Java.
	"bat",
	"cmd",
	"js",
	"jse",
	"vbs",
	"vbe",
	"wsf",
	"wsh",
	"ps1",
	"ps1xml",
	"psc1",
	"jar",
	// HTML applications and compiled help, which run script with the
	// user's rights.
	"hta",
	"chm",
	// Installers and patches, management console snap-ins, registry files.
	"msi",
	"msp",
	"mst",
	"msc",
	"reg",
	// Shortcuts that open a program or a remote location: shell links,
	// Explorer commands, Internet and pinned-site shortcuts, ClickOnce
	// deployments, desktop gadgets.
	"lnk",
	"scf",
	"url",
	"website",
	"appref-ms",
	"application",
	"gadget",
	// Disk images, which mount and hide their content from a scan.
	"iso",
];

/// The dangerous extension set (the built-in list plus
/// `block_extensions`) and the operator's `allow_extensions`. An allowed
/// extension only cancels what its own name says: see
/// [`Extensions::covering`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extensions {
	blocked: BTreeSet<String>,
	allowed: BTreeSet<String>,
}

impl Extensions {
	/// Build the set from the operator's lists, which are already
	/// validated (lower case, no leading dot). An always-dangerous
	/// extension in `allow` is ignored.
	pub fn new(block: &[String], allow: &[String]) -> Self {
		let mut blocked: BTreeSet<String> = DANGEROUS_EXTENSIONS
			.iter()
			.map(|ext| ext.to_string())
			.collect();
		blocked.extend(block.iter().cloned());
		Self {
			blocked,
			allowed: allow
				.iter()
				.filter(|ext| !ALWAYS_DANGEROUS.contains(&ext.as_str()))
				.cloned()
				.collect(),
		}
	}

	/// The allowed extension every reading of every name ends in, if there
	/// is one: only then does the allowance apply. No names, names that
	/// disagree, or a double extension such as `a.svg.exe` are not covered.
	pub fn covering(&self, names: &[String]) -> Option<String> {
		let mut common: Option<String> = None;
		for name in names {
			for variant in name_variants(name) {
				let ext = extensions_of(&variant).0?;
				match &common {
					None => common = Some(ext),
					Some(seen) if *seen == ext => {}
					Some(_) => return None,
				}
			}
		}
		common.filter(|ext| self.allowed.contains(ext))
	}

	fn is_dangerous(&self, ext: &str) -> bool {
		self.blocked.contains(ext)
	}
}

impl Default for Extensions {
	fn default() -> Self {
		Self::new(&[], &[])
	}
}

/// The facts about one attachment the rules read.
pub struct Facts<'a> {
	/// Every candidate file name; empty when the part has none.
	pub filenames: &'a [String],
	/// Every declared `type/subtype`, lower case.
	pub declared_types: &'a [String],
	/// The content's real type.
	pub real_type: RealType,
	/// The zip directory, when the content opens as a zip.
	pub listing: Option<&'a Listing>,
	/// The OLE2 directory, when the content is OLE2.
	pub ole: Option<Ole>,
}

/// Judge one attachment: every rule runs on every reading of every
/// candidate name and on every declared type, and a finding from any of
/// them stands. The result is sorted and has no duplicates.
pub fn judge(facts: &Facts<'_>, extensions: &Extensions) -> Vec<Reason> {
	let mut reasons = BTreeSet::new();
	if facts.filenames.iter().any(|name| name.contains(FORMATTING)) {
		reasons.insert(Reason::BidiName);
	}
	let covered = extensions.covering(facts.filenames);
	let mut claimed: Vec<Option<String>> = Vec::new();
	for name in facts.filenames.iter().flat_map(|name| name_variants(name)) {
		let (last, previous) = extensions_of(&name);
		if let Some(ext) = last.as_deref() {
			if extensions.is_dangerous(ext) && covered.as_deref() != Some(ext) {
				reasons.insert(Reason::DangerousExtension);
				if previous
					.as_deref()
					.is_some_and(|prev| DECOY_EXTENSIONS.contains(&prev))
				{
					reasons.insert(Reason::DoubleExtension);
				}
			}
			if HTML_EXTENSIONS.contains(&ext) {
				reasons.insert(Reason::HtmlAttachment);
			}
		}
		claimed.push(last);
	}
	if claimed.is_empty() {
		claimed.push(None);
	}
	let real = facts.real_type;
	if real.is_executable() {
		reasons.insert(Reason::ExecutableContent);
	}
	if real == RealType::Iso {
		reasons.insert(Reason::DiskImage);
	}
	if real == RealType::Html {
		reasons.insert(Reason::HtmlAttachment);
	}
	if matches!(real, RealType::Rar | RealType::SevenZip) {
		reasons.insert(Reason::UnreadableArchive);
	}
	// The bytes decide: an image or PDF claim, by any name or any declared
	// type, on content of another format, or on content that is not the
	// claimed format at all, is a disguise.
	let declared: Vec<&str> = if facts.declared_types.is_empty() {
		vec![""]
	} else {
		facts.declared_types.iter().map(String::as_str).collect()
	};
	for ext in &claimed {
		for kind in &declared {
			let ext = ext.as_deref();
			let mismatched_image = claims_image(ext, kind)
				&& !real.is_image()
				&& (real != RealType::Unknown || claims_sniffable_image(ext, kind));
			let mismatched_pdf = claims_pdf(ext, kind) && real != RealType::Pdf;
			let mismatched_svg =
				claims_svg(ext, kind) && real != RealType::Svg && real != RealType::Unknown;
			if mismatched_image || mismatched_pdf || mismatched_svg {
				reasons.insert(Reason::TypeMismatch);
			}
		}
	}
	if let Some(listing) = facts.listing {
		judge_listing(listing, real, extensions, &mut reasons);
	}
	if let Some(ole) = facts.ole {
		if ole.macros {
			reasons.insert(Reason::Macro);
		}
		if ole.encrypted {
			reasons.insert(Reason::EncryptedArchive);
		}
		if ole.unreadable {
			reasons.insert(Reason::UnreadableArchive);
		}
	}
	reasons.into_iter().collect()
}

fn judge_listing(
	listing: &Listing,
	real: RealType,
	extensions: &Extensions,
	reasons: &mut BTreeSet<Reason>,
) {
	if listing.encrypted {
		reasons.insert(Reason::EncryptedArchive);
	}
	if listing.too_many {
		reasons.insert(Reason::ScanLimit);
	}
	if listing.unreadable {
		reasons.insert(Reason::UnreadableArchive);
	}
	if listing.ambiguous {
		reasons.insert(Reason::AmbiguousArchive);
	}
	for entry in &listing.names {
		if entry.contains(FORMATTING) {
			reasons.insert(Reason::DangerousArchiveEntry);
		}
		for name in name_variants(entry) {
			let Some(ext) = extensions_of(&name).0 else {
				continue;
			};
			if extensions.is_dangerous(&ext) {
				reasons.insert(Reason::DangerousArchiveEntry);
			}
			if ARCHIVE_EXTENSIONS.contains(&ext.as_str()) {
				reasons.insert(Reason::NestedArchive);
			}
		}
	}
	if matches!(real, RealType::Ooxml | RealType::Zip) && super::archive::ooxml_has_macros(listing)
	{
		reasons.insert(Reason::Macro);
	}
}

/// Every way a client or an extractor may read `name`, each reduced to
/// the name a file system would open: formatting characters removed;
/// whole and cut at the first NUL (C extractors stop there); as written
/// and folded with NFKC plus the dots and slashes NFKC leaves alone
/// (`photo\u{ff0e}exe` reads as `photo.exe`); then the last path
/// component, without the trailing dots and spaces Windows drops
/// (`a.pdf.exe.` and `a.pdf.exe ` both open `a.pdf.exe`) and also cut at
/// the first colon, the alternate data stream suffix NTFS ignores
/// (`a.exe::$DATA` opens `a.exe`).
pub(super) fn name_variants(name: &str) -> Vec<String> {
	use unicode_normalization::UnicodeNormalization as _;
	let visible: String = name.chars().filter(|c| !FORMATTING.contains(c)).collect();
	let mut forms = vec![visible.clone()];
	if let Some((head, _)) = visible.split_once('\0') {
		forms.push(head.to_string());
	}
	let folded: Vec<String> = forms
		.iter()
		.map(|form| {
			form.nfkc()
				.map(|c| match c {
					'\u{3002}' | '\u{ff61}' | '\u{fe12}' => '.',
					'\u{2215}' | '\u{2044}' | '\u{29f8}' => '/',
					'\u{29f5}' | '\u{29f9}' => '\\',
					other => other,
				})
				.collect()
		})
		.collect();
	forms.extend(folded);
	let mut variants: Vec<String> = Vec::new();
	for form in forms {
		let base = form.rsplit(['/', '\\']).next().unwrap_or(&form);
		// NTFS opens `a.exe::$DATA` and `a.exe:stream` as `a.exe`: the name
		// is also read up to the first colon.
		let stream_less = base.split(':').next().unwrap_or(base);
		for read in [base, stream_less] {
			let trimmed = read
				.trim_end_matches(|c: char| c == '.' || c.is_whitespace())
				.to_string();
			if !variants.contains(&trimmed) {
				variants.push(trimmed);
			}
		}
	}
	variants
}

/// The last and second-to-last extensions, lower case and trimmed, so
/// `a.pdf .exe` yields (`exe`, `pdf`).
fn extensions_of(name: &str) -> (Option<String>, Option<String>) {
	let mut pieces = name.rsplit('.');
	let last = pieces.next();
	let previous = pieces.next();
	let has_dot = name.contains('.');
	let clean = |piece: &str| piece.trim().to_lowercase();
	match (has_dot, last, previous) {
		(true, Some(last), previous) => (
			Some(clean(last)),
			previous
				.filter(|_| name.matches('.').count() >= 2)
				.map(clean),
		),
		_ => (None, None),
	}
}

/// A raster image claim. SVG is not one: it is judged as active-image.
fn claims_image(ext: Option<&str>, declared_type: &str) -> bool {
	ext.is_some_and(|ext| IMAGE_EXTENSIONS.contains(&ext))
		|| declared_type.starts_with("image/") && declared_type != "image/svg+xml"
}

fn claims_sniffable_image(ext: Option<&str>, declared_type: &str) -> bool {
	ext.is_some_and(|ext| IMAGE_EXTENSIONS.contains(&ext))
		|| SNIFFABLE_IMAGE_TYPES.contains(&declared_type)
}

fn claims_svg(ext: Option<&str>, declared_type: &str) -> bool {
	matches!(ext, Some("svg" | "svgz")) || declared_type == "image/svg+xml"
}

fn claims_pdf(ext: Option<&str>, declared_type: &str) -> bool {
	ext == Some("pdf") || declared_type == "application/pdf"
}

#[cfg(test)]
mod tests;
