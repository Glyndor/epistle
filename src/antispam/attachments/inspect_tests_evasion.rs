//! Evasions aimed at the gap between what the scan reads and what a client
//! shows or saves.

use super::*;
use crate::antispam::attachments::corpus::{self, attachment};

fn inspect_default(raw: &[u8]) -> Report {
	inspect(raw, &Extensions::default(), Budget::bytes(1 << 20))
}

#[test]
fn every_candidate_name_is_judged() {
	let raw = corpus::message(&[attachment(
		"Content-Type: application/pdf; name=\"invoice.exe\"\r\n\
		 Content-Disposition: attachment; filename=\"invoice.pdf\"",
		&corpus::pdf(),
	)]);
	let report = inspect_default(&raw);
	assert_eq!(report.parts.len(), 1);
	assert_eq!(report.parts[0].filename.as_deref(), Some("invoice.pdf"));
	assert_eq!(
		report.parts[0].reasons,
		vec![Reason::DangerousExtension, Reason::AmbiguousMime]
	);
}

#[test]
fn an_ambiguous_structure_is_reported() {
	let raw = b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\
		Content-Type: text/plain\r\n\r\nhi\r\n--ABC\r\n\
		Content-Type: application/octet-stream; name=a.exe\r\n\r\nMZ\r\n--abc--\r\n";
	let report = inspect_default(raw);
	assert!(report.ambiguous);
	assert_eq!(report.reasons(), vec![Reason::AmbiguousMime]);
}

#[test]
fn an_operator_can_allow_svg() {
	let raw = corpus::message(&[attachment(
		"Content-Type: image/svg+xml; name=logo.svg",
		b"<svg><rect/></svg>",
	)]);
	let allow = Extensions::new(&[], &["svg".to_string()]);
	assert_eq!(
		inspect(&raw, &Extensions::default(), Budget::bytes(1 << 20)).reasons(),
		vec![Reason::ActiveImage]
	);
	assert!(
		inspect(&raw, &allow, Budget::bytes(1 << 20))
			.reasons()
			.is_empty()
	);
}
