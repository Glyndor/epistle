//! The disguises from end to end: a raw message in, the verdicts out.

use super::*;
use crate::antispam::attachments::corpus::{self, ZipEntry, attachment};

fn inspect_default(raw: &[u8]) -> Report {
	inspect(raw, &Extensions::default(), Budget::bytes(1 << 20))
}

fn only_part(report: &Report) -> &PartReport {
	assert_eq!(report.parts.len(), 1, "one attachment expected");
	&report.parts[0]
}

#[test]
fn an_executable_renamed_as_an_image_is_caught() {
	let raw = corpus::message(&[attachment(
		"Content-Type: image/jpeg\r\nContent-Disposition: attachment; filename=\"holiday.jpg\"",
		&corpus::pe(),
	)]);
	let report = inspect_default(&raw);
	let part = only_part(&report);
	assert_eq!(part.filename.as_deref(), Some("holiday.jpg"));
	assert_eq!(part.declared_type, "image/jpeg");
	assert_eq!(part.real_type, RealType::Pe);
	assert_eq!(
		part.reasons,
		vec![Reason::ExecutableContent, Reason::TypeMismatch]
	);
}

#[test]
fn a_script_inside_a_zip_is_caught() {
	let raw = corpus::message(&[attachment(
		"Content-Type: application/zip; name=\"docs.zip\"",
		&corpus::zip_of(&["invoice.pdf", "x.js"]),
	)]);
	let report = inspect_default(&raw);
	let part = only_part(&report);
	assert_eq!(part.real_type, RealType::Zip);
	assert_eq!(part.reasons, vec![Reason::DangerousArchiveEntry]);
}

#[test]
fn a_double_extension_and_a_right_to_left_override_are_caught() {
	let raw = corpus::message(&[
		attachment(
			"Content-Type: application/pdf; name=\"factura.pdf.exe\"",
			b"%PDF-1.4",
		),
		attachment(
			"Content-Type: application/octet-stream; name=\"=?utf-8?q?pay=E2=80=AEfdp.scr?=\"",
			b"data",
		),
	]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts.len(), 2);
	assert_eq!(
		report.parts[0].reasons,
		vec![Reason::DangerousExtension, Reason::DoubleExtension]
	);
	assert_eq!(
		report.parts[1].filename.as_deref(),
		Some("pay\u{202e}fdp.scr")
	);
	assert_eq!(
		report.parts[1].reasons,
		vec![Reason::DangerousExtension, Reason::BidiName]
	);
}

#[test]
fn a_macro_enabled_document_is_caught() {
	let raw = corpus::message(&[
		attachment(
			"Content-Type: application/vnd.ms-word.document.macroEnabled.12; name=\"q3.docm\"",
			&corpus::zip_of(&[
				"[Content_Types].xml",
				"word/document.xml",
				"word/vbaProject.bin",
			]),
		),
		attachment(
			"Content-Type: application/msword; name=\"old.doc\"",
			&corpus::ole2("_VBA_PROJECT"),
		),
	]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts.len(), 2);
	assert_eq!(report.parts[0].real_type, RealType::Ooxml);
	assert_eq!(report.parts[0].reasons, vec![Reason::Macro]);
	assert_eq!(report.parts[1].real_type, RealType::Ole2);
	assert_eq!(report.parts[1].reasons, vec![Reason::Macro]);
}

#[test]
fn an_encrypted_zip_is_caught() {
	let raw = corpus::message(&[attachment(
		"Content-Type: application/zip; name=\"secure.zip\"",
		&corpus::zip(&[ZipEntry {
			name: "statement.pdf",
			encrypted: true,
		}]),
	)]);
	let report = inspect_default(&raw);
	assert_eq!(only_part(&report).reasons, vec![Reason::EncryptedArchive]);
	assert_eq!(report.reasons(), vec![Reason::EncryptedArchive]);
}

#[test]
fn a_part_bomb_and_deep_nesting_are_too_complex() {
	let mut bomb = String::from("Content-Type: multipart/mixed; boundary=z\r\n\r\n");
	for _ in 0..1200 {
		bomb.push_str("--z\r\nContent-Type: text/plain\r\n\r\nx\r\n");
	}
	bomb.push_str("--z--\r\n");
	let report = inspect_default(bomb.as_bytes());
	assert_eq!(report.stopped, Some(Stop::TooManyParts));
	assert_eq!(report.reasons(), vec![Reason::ScanLimit]);

	let mut deep = String::new();
	for level in 0..40 {
		deep.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"d{level}\"\r\n\r\n--d{level}\r\n"
		));
	}
	let report = inspect_default(deep.as_bytes());
	assert_eq!(report.stopped, Some(Stop::TooDeep));
	assert_eq!(report.reasons(), vec![Reason::ScanLimit]);
}

#[test]
fn ordinary_attachments_pass_clean() {
	let raw = corpus::message(&[
		attachment(
			"Content-Type: image/png; name=\"chart.png\"",
			&corpus::png(),
		),
		attachment(
			"Content-Type: application/pdf; name=\"report.pdf\"",
			&corpus::pdf(),
		),
		attachment(
			"Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"cv.docx\"",
			&corpus::zip_of(&["[Content_Types].xml", "word/document.xml"]),
		),
	]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts.len(), 3);
	assert_eq!(
		report
			.parts
			.iter()
			.map(|part| part.real_type)
			.collect::<Vec<_>>(),
		vec![RealType::Png, RealType::Pdf, RealType::Ooxml]
	);
	assert!(report.reasons().is_empty(), "{:?}", report.reasons());
}

#[test]
fn a_zip_cut_by_the_decode_budget_is_not_listed() {
	let mut names: Vec<String> = (0..3000).map(|i| format!("file-{i:05}.txt")).collect();
	names.push("payload.js".into());
	let names: Vec<&str> = names.iter().map(String::as_str).collect();
	let raw = corpus::message(&[attachment(
		"Content-Type: application/zip; name=\"big.zip\"",
		&corpus::zip_of(&names),
	)]);
	let report = inspect(&raw, &Extensions::default(), Budget::bytes(1024));
	let part = only_part(&report);
	assert_eq!(part.real_type, RealType::Zip);
	assert_eq!(
		part.reasons,
		vec![Reason::ScanLimit],
		"a prefix cannot be listed, so it is not clean"
	);
}
