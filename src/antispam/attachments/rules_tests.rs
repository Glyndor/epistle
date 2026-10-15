use super::*;
use crate::antispam::attachments::archive::{Listing, Ole, list_zip};
use crate::antispam::attachments::corpus;

fn named(name: &str, declared: &str, real: RealType) -> Vec<Reason> {
	judge(
		&Facts {
			filenames: &[name.to_string()],
			declared_types: &[declared.to_string()],
			real_type: real,
			listing: None,
			ole: None,
		},
		&Extensions::default(),
	)
}

fn archive(listing: &Listing, real: RealType) -> Vec<Reason> {
	judge(
		&Facts {
			filenames: &["files.zip".to_string()],
			declared_types: &["application/zip".to_string()],
			real_type: real,
			listing: Some(listing),
			ole: None,
		},
		&Extensions::default(),
	)
}

#[test]
fn a_decoy_extension_before_a_dangerous_one_is_a_double_extension() {
	assert_eq!(
		named("factura.pdf.exe", "application/pdf", RealType::Unknown),
		vec![
			Reason::DangerousExtension,
			Reason::DoubleExtension,
			Reason::TypeMismatch
		]
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
		vec![
			Reason::DangerousExtension,
			Reason::BidiName,
			Reason::TypeMismatch
		]
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
		vec![Reason::TypeMismatch, Reason::UnreadableArchive]
	);
	// Another image format, or an image type the table has no signature
	// for, is not a disguise.
	assert!(named("photo.jpg", "image/jpeg", RealType::Png).is_empty());
	assert!(named("photo.jxl", "image/jxl", RealType::Unknown).is_empty());
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
	// SVG is not judged here: any SVG reading is active-image, decided
	// with the content in the inspection.
	assert!(named("logo.svg", "image/svg+xml", RealType::Unknown).is_empty());
}

#[test]
fn block_and_allow_lists_change_the_extension_set() {
	let extensions = Extensions::new(&["docx".to_string()], &["inf".to_string()]);
	let judge_name = |name: &str| {
		judge(
			&Facts {
				filenames: &[name.to_string()],
				declared_types: &["application/octet-stream".to_string()],
				real_type: RealType::Unknown,
				listing: None,
				ole: None,
			},
			&extensions,
		)
	};
	assert_eq!(judge_name("report.docx"), vec![Reason::DangerousExtension]);
	assert!(judge_name("setup.inf").is_empty());
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
		unreadable: false,
		ambiguous: false,
	};
	assert_eq!(
		archive(&encrypted, RealType::Zip),
		vec![Reason::EncryptedArchive]
	);
	let crowded = Listing {
		names: vec!["a.txt".into()],
		encrypted: false,
		too_many: true,
		unreadable: false,
		ambiguous: false,
	};
	assert_eq!(archive(&crowded, RealType::Zip), vec![Reason::ScanLimit]);
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
			filenames: &["old.doc".to_string()],
			declared_types: &["application/msword".to_string()],
			real_type: RealType::Ole2,
			listing: None,
			ole: Some(Ole {
				macros: true,
				..Ole::default()
			}),
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
			"active-image",
			"appended-payload",
			"ambiguous-image",
			"dangerous-archive-entry",
			"nested-archive",
			"encrypted-archive",
			"unreadable-archive",
			"ambiguous-archive",
			"macro",
			"ambiguous-mime",
			"scan-limit",
		]
	);
}

#[test]
fn every_declared_type_is_checked_against_the_bytes() {
	let reasons = judge(
		&Facts {
			filenames: &[],
			declared_types: &[
				"application/octet-stream".to_string(),
				"image/png".to_string(),
			],
			real_type: RealType::Zip,
			listing: None,
			ole: None,
		},
		&Extensions::default(),
	);
	assert_eq!(reasons, vec![Reason::TypeMismatch]);
}

#[test]
fn a_name_is_judged_whole_and_cut_at_a_nul() {
	assert_eq!(
		named(
			"notes.txt\0x.exe",
			"application/octet-stream",
			RealType::Unknown
		),
		vec![Reason::DangerousExtension]
	);
	assert_eq!(
		named(
			"x.exe\0notes.txt",
			"application/octet-stream",
			RealType::Unknown
		),
		vec![Reason::DangerousExtension]
	);
}

#[test]
fn svg_bytes_behind_a_raster_claim_are_a_mismatch_but_not_under_their_own_type() {
	assert_eq!(
		named("logo.png", "image/png", RealType::Svg),
		vec![Reason::TypeMismatch]
	);
	assert!(named("logo.svg", "image/svg+xml", RealType::Svg).is_empty());
}

#[test]
fn an_allowance_covers_only_its_own_name() {
	let allow = Extensions::new(&[], &["inf".to_string(), "exe".to_string()]);
	let judge_names = |names: &[&str]| {
		let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
		judge(
			&Facts {
				filenames: &names,
				declared_types: &["application/octet-stream".to_string()],
				real_type: RealType::Unknown,
				listing: None,
				ole: None,
			},
			&allow,
		)
	};
	assert!(judge_names(&["setup.inf"]).is_empty());
	assert_eq!(
		judge_names(&["setup.inf", "setup.txt"]),
		vec![Reason::DangerousExtension],
		"names that disagree are not covered"
	);
	assert_eq!(
		judge_names(&["photo.inf.scr"]),
		vec![Reason::DangerousExtension],
		"a double extension is not covered"
	);
	assert_eq!(
		judge_names(&["setup.exe"]),
		vec![Reason::DangerousExtension],
		"an always-dangerous extension is never allowed"
	);
	let entries = list_zip(&corpus::zip_of(&["setup.inf"]));
	assert_eq!(
		judge(
			&Facts {
				filenames: &["setup.inf".to_string()],
				declared_types: &["application/zip".to_string()],
				real_type: RealType::Zip,
				listing: Some(&entries),
				ole: None,
			},
			&allow,
		),
		vec![Reason::DangerousArchiveEntry],
		"the allowance never reaches archive entries"
	);
}
