use super::*;
use crate::antispam::attachments::archive::{Listing, list_zip};
use crate::antispam::attachments::corpus;

fn named(name: &str, declared: &str, real: RealType) -> Vec<Reason> {
	judge(
		&Facts {
			filename: Some(name),
			declared_type: declared,
			real_type: real,
			listing: None,
			ole_macros: false,
		},
		&Extensions::default(),
	)
}

fn archive(listing: &Listing, real: RealType) -> Vec<Reason> {
	judge(
		&Facts {
			filename: Some("files.zip"),
			declared_type: "application/zip",
			real_type: real,
			listing: Some(listing),
			ole_macros: false,
		},
		&Extensions::default(),
	)
}

#[test]
fn a_decoy_extension_before_a_dangerous_one_is_a_double_extension() {
	assert_eq!(
		named("factura.pdf.exe", "application/pdf", RealType::Unknown),
		vec![Reason::DangerousExtension, Reason::DoubleExtension]
	);
	assert_eq!(
		named("setup.exe", "application/octet-stream", RealType::Unknown),
		vec![Reason::DangerousExtension]
	);
}

#[test]
fn trailing_dots_and_spaces_do_not_hide_the_extension() {
	for name in [
		"a.pdf.exe.",
		"a.pdf.exe ",
		"a.pdf .exe",
		"a.pdf.EXE. . ",
		"dir\\a.pdf.exe",
	] {
		assert_eq!(
			named(name, "application/octet-stream", RealType::Unknown),
			vec![Reason::DangerousExtension, Reason::DoubleExtension],
			"name {name:?}"
		);
	}
}

#[test]
fn a_right_to_left_override_is_flagged_and_the_real_extension_judged() {
	assert_eq!(
		named("invoice\u{202e}gpj.exe", "image/jpeg", RealType::Unknown),
		vec![Reason::DangerousExtension, Reason::BidiName]
	);
	assert_eq!(
		named("notes\u{202e}txt.md", "text/plain", RealType::Unknown),
		vec![Reason::BidiName]
	);
}

#[test]
fn executable_content_is_flagged_whatever_the_name_says() {
	assert_eq!(
		named("photo.jpg", "image/jpeg", RealType::Pe),
		vec![Reason::ExecutableContent, Reason::TypeMismatch]
	);
	assert_eq!(
		named("notes.txt", "text/plain", RealType::Script),
		vec![Reason::ExecutableContent]
	);
	assert_eq!(
		named("disk.dat", "application/octet-stream", RealType::Iso),
		vec![Reason::DiskImage]
	);
}

#[test]
fn an_image_or_pdf_that_is_something_else_is_a_type_mismatch() {
	assert_eq!(
		named("photo.png", "image/png", RealType::Zip),
		vec![Reason::TypeMismatch]
	);
	assert_eq!(
		named("scan.pdf", "application/pdf", RealType::Ole2),
		vec![Reason::TypeMismatch]
	);
	assert_eq!(
		named("unnamed", "image/gif", RealType::Rar),
		vec![Reason::TypeMismatch]
	);
	// Another image format, or bytes the table does not know, are not a
	// disguise.
	assert!(named("photo.jpg", "image/jpeg", RealType::Png).is_empty());
	assert!(named("photo.heic", "image/heic", RealType::Unknown).is_empty());
	assert!(named("scan.pdf", "application/pdf", RealType::Pdf).is_empty());
}

#[test]
fn html_attachments_are_flagged_by_name_or_content() {
	assert_eq!(
		named("login.html", "text/html", RealType::Html),
		vec![Reason::HtmlAttachment]
	);
	assert_eq!(
		named("statement.txt", "text/plain", RealType::Html),
		vec![Reason::HtmlAttachment]
	);
	assert_eq!(
		named("logo.svg", "image/svg+xml", RealType::Unknown),
		vec![Reason::HtmlAttachment]
	);
}

#[test]
fn block_and_allow_lists_change_the_extension_set() {
	let extensions = Extensions::new(&["docx".to_string()], &["js".to_string()]);
	let judge_name = |name: &str| {
		judge(
			&Facts {
				filename: Some(name),
				declared_type: "application/octet-stream",
				real_type: RealType::Unknown,
				listing: None,
				ole_macros: false,
			},
			&extensions,
		)
	};
	assert_eq!(judge_name("report.docx"), vec![Reason::DangerousExtension]);
	assert!(judge_name("app.js").is_empty());
	assert_eq!(judge_name("run.exe"), vec![Reason::DangerousExtension]);
}

#[test]
fn archive_entries_encryption_and_size_are_judged() {
	assert_eq!(
		archive(
			&list_zip(&corpus::zip_of(&["readme.txt", "x.js"])),
			RealType::Zip
		),
		vec![Reason::DangerousArchiveEntry]
	);
	assert_eq!(
		archive(
			&list_zip(&corpus::zip_of(&["a\u{202e}fdp.scr"])),
			RealType::Zip
		),
		vec![Reason::DangerousArchiveEntry]
	);
	let encrypted = Listing {
		names: vec!["a.pdf".into()],
		encrypted: true,
		too_many: false,
	};
	assert_eq!(
		archive(&encrypted, RealType::Zip),
		vec![Reason::EncryptedArchive]
	);
	let crowded = Listing {
		names: vec!["a.txt".into()],
		encrypted: false,
		too_many: true,
	};
	assert_eq!(
		archive(&crowded, RealType::Zip),
		vec![Reason::ArchiveTooComplex]
	);
	assert!(archive(&list_zip(&corpus::zip_of(&["a.txt"])), RealType::Zip).is_empty());
}

#[test]
fn office_macros_are_flagged() {
	let docm = list_zip(&corpus::zip_of(&[
		"[Content_Types].xml",
		"word/vbaProject.bin",
	]));
	assert_eq!(archive(&docm, RealType::Ooxml), vec![Reason::Macro]);
	let ole = judge(
		&Facts {
			filename: Some("old.doc"),
			declared_type: "application/msword",
			real_type: RealType::Ole2,
			listing: None,
			ole_macros: true,
		},
		&Extensions::default(),
	);
	assert_eq!(ole, vec![Reason::Macro]);
}

#[test]
fn reason_codes_are_stable() {
	let codes: Vec<&str> = [
		Reason::DangerousExtension,
		Reason::DoubleExtension,
		Reason::BidiName,
		Reason::ExecutableContent,
		Reason::DiskImage,
		Reason::TypeMismatch,
		Reason::HtmlAttachment,
		Reason::DangerousArchiveEntry,
		Reason::EncryptedArchive,
		Reason::ArchiveTooComplex,
		Reason::Macro,
		Reason::MimeTooComplex,
	]
	.iter()
	.map(|reason| reason.code())
	.collect();
	assert_eq!(
		codes,
		vec![
			"dangerous-extension",
			"double-extension",
			"bidi-name",
			"executable-content",
			"disk-image",
			"type-mismatch",
			"html-attachment",
			"dangerous-archive-entry",
			"encrypted-archive",
			"archive-too-complex",
			"macro",
			"mime-too-complex",
		]
	);
}
