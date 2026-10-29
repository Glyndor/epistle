//! `docs/attachments.md` names every reason code and every extension no
//! allowance may cover, so the page cannot fall behind the code.

use super::rules::{ALWAYS_DANGEROUS, Reason};

const REASONS: &[Reason] = &[
	Reason::DangerousExtension,
	Reason::DoubleExtension,
	Reason::BidiName,
	Reason::ExecutableContent,
	Reason::DiskImage,
	Reason::TypeMismatch,
	Reason::HtmlAttachment,
	Reason::ActiveImage,
	Reason::AppendedPayload,
	Reason::AmbiguousImage,
	Reason::DangerousArchiveEntry,
	Reason::NestedArchive,
	Reason::EncryptedArchive,
	Reason::UnreadableArchive,
	Reason::AmbiguousArchive,
	Reason::Macro,
	Reason::AmbiguousMime,
	Reason::ScanLimit,
];

#[test]
fn the_page_names_every_code_and_every_always_dangerous_extension() {
	let page = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/attachments.md"))
		.unwrap_or_default();
	let codes: Vec<&str> = REASONS
		.iter()
		.map(|reason| reason.code())
		.filter(|code| !page.contains(&format!("| `{code}` |")))
		.collect();
	let extensions: Vec<&str> = ALWAYS_DANGEROUS
		.iter()
		.copied()
		.filter(|ext| !page.contains(&format!("`{ext}`")))
		.collect();
	assert_eq!(
		(codes, extensions),
		(Vec::<&str>::new(), Vec::<&str>::new()),
		"(reason codes, always-dangerous extensions) missing from docs/attachments.md"
	);
}
