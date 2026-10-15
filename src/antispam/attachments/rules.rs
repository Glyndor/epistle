//! The rules that judge one attachment: each finding is a [`Reason`] with a
//! stable code, the only thing that ever reaches a header or a log.

use std::collections::BTreeSet;

use super::archive::Listing;
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

const IMAGE_EXTENSIONS: &[&str] = &[
	"jpg", "jpeg", "jpe", "png", "gif", "webp", "bmp", "tif", "tiff", "ico", "heic",
];

const HTML_EXTENSIONS: &[&str] = &[
	"htm", "html", "shtml", "xht", "xhtml", "mht", "mhtml", "svg",
];

/// Bidirectional and zero-width formatting characters. U+202E (RIGHT-TO-LEFT
/// OVERRIDE) makes `invoice<RLO>gpj.exe` display as `invoiceexe.jpg`.
const BIDI_CONTROLS: &[char] = &[
	'\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}',
	'\u{2067}', '\u{2068}', '\u{2069}',
];

/// Why an attachment was singled out. The codes are a stable interface:
/// they appear in `X-Epistle-Attachment-Warning` and in command output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
	/// The name ends in an extension that runs or mounts when opened.
	DangerousExtension,
	/// A decoy extension sits before a dangerous one: `factura.pdf.exe`.
	DoubleExtension,
	/// The name carries bidirectional formatting characters.
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
	/// An archive holds an entry with a dangerous extension.
	DangerousArchiveEntry,
	/// An archive holds encrypted entries no scanner can read.
	EncryptedArchive,
	/// An archive has more entries than are listed.
	ArchiveTooComplex,
	/// An Office document carries a VBA project.
	Macro,
	/// The message is nested too deeply, has too many parts or a header
	/// block too large to inspect.
	MimeTooComplex,
	/// Two mail clients could read the MIME structure, a header or an
	/// encoding differently.
	AmbiguousMime,
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
			Self::DangerousArchiveEntry => "dangerous-archive-entry",
			Self::EncryptedArchive => "encrypted-archive",
			Self::ArchiveTooComplex => "archive-too-complex",
			Self::Macro => "macro",
			Self::MimeTooComplex => "mime-too-complex",
			Self::AmbiguousMime => "ambiguous-mime",
		}
	}
}

/// The effective dangerous extension set: the built-in list plus
/// `block_extensions`, minus `allow_extensions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extensions {
	blocked: BTreeSet<String>,
}

impl Extensions {
	/// Build the set from the operator's lists, which are already
	/// validated (lower case, no leading dot).
	pub fn new(block: &[String], allow: &[String]) -> Self {
		let mut blocked: BTreeSet<String> = DANGEROUS_EXTENSIONS
			.iter()
			.map(|ext| ext.to_string())
			.collect();
		blocked.extend(block.iter().cloned());
		for ext in allow {
			blocked.remove(ext);
		}
		Self { blocked }
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
	/// The declared file name, if any.
	pub filename: Option<&'a str>,
	/// The declared `type/subtype`, lower case.
	pub declared_type: &'a str,
	/// The content's real type.
	pub real_type: RealType,
	/// The zip directory, when the content is a zip.
	pub listing: Option<&'a Listing>,
	/// An OLE2 file with a VBA project.
	pub ole_macros: bool,
}

/// Judge one attachment. The result is sorted and has no duplicates.
pub fn judge(facts: &Facts<'_>, extensions: &Extensions) -> Vec<Reason> {
	let mut reasons = BTreeSet::new();
	let name = facts.filename.map(normalise_name);
	if facts
		.filename
		.is_some_and(|name| name.contains(BIDI_CONTROLS))
	{
		reasons.insert(Reason::BidiName);
	}
	let (last, previous) = name.as_deref().map(extensions_of).unwrap_or((None, None));
	if let Some(ext) = last.as_deref() {
		if extensions.is_dangerous(ext) {
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
	if claims_image(last.as_deref(), facts.declared_type)
		&& real != RealType::Unknown
		&& !real.is_image()
		|| claims_pdf(last.as_deref(), facts.declared_type)
			&& real != RealType::Unknown
			&& real != RealType::Pdf
	{
		reasons.insert(Reason::TypeMismatch);
	}
	if let Some(listing) = facts.listing {
		if listing.encrypted {
			reasons.insert(Reason::EncryptedArchive);
		}
		if listing.too_many {
			reasons.insert(Reason::ArchiveTooComplex);
		}
		if listing.names.iter().any(|entry| {
			entry.contains(BIDI_CONTROLS)
				|| extensions_of(&normalise_name(entry))
					.0
					.is_some_and(|ext| extensions.is_dangerous(&ext))
		}) {
			reasons.insert(Reason::DangerousArchiveEntry);
		}
		if real == RealType::Ooxml && super::archive::ooxml_has_macros(listing) {
			reasons.insert(Reason::Macro);
		}
	}
	if facts.ole_macros {
		reasons.insert(Reason::Macro);
	}
	reasons.into_iter().collect()
}

/// The name as Windows would open it: the last path component, without
/// bidirectional controls, and without the trailing dots and spaces the
/// file system drops (`a.pdf.exe.` and `a.pdf.exe ` both open `a.pdf.exe`).
fn normalise_name(name: &str) -> String {
	let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
	let cleaned: String = base
		.chars()
		.filter(|c| !BIDI_CONTROLS.contains(c))
		.collect();
	cleaned
		.trim_end_matches(|c: char| c == '.' || c.is_whitespace())
		.to_string()
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

fn claims_image(ext: Option<&str>, declared_type: &str) -> bool {
	ext.is_some_and(|ext| IMAGE_EXTENSIONS.contains(&ext)) || declared_type.starts_with("image/")
}

fn claims_pdf(ext: Option<&str>, declared_type: &str) -> bool {
	ext == Some("pdf") || declared_type == "application/pdf"
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
