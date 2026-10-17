use std::io::Write as _;

use super::*;
use crate::antispam::attachments::corpus;

pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(bytes).expect("gzip");
	encoder.finish().expect("gzip")
}

pub(crate) fn utf16(text: &str, little: bool, mark: bool) -> Vec<u8> {
	let mut out = Vec::new();
	if mark {
		out.extend_from_slice(if little { b"\xff\xfe" } else { b"\xfe\xff" });
	}
	for unit in text.encode_utf16() {
		out.extend_from_slice(&if little {
			unit.to_le_bytes()
		} else {
			unit.to_be_bytes()
		});
	}
	out
}

#[test]
fn an_svg_element_is_found_in_every_reading() {
	let padded = format!("<!--{}--><!DOCTYPE svg><svg/>", "c".repeat(4000));
	for (case, bytes) in [
		("plain", b"<svg/>".to_vec()),
		(
			"upper case after a bom",
			b"\xef\xbb\xbf <SVG width='1'>".to_vec(),
		),
		(
			"prefixed",
			b"<x:svg xmlns:x='http://www.w3.org/2000/svg'/>".to_vec(),
		),
		(
			"nested in another root",
			b"<?xml version='1.0'?><doc><svg/></doc>".to_vec(),
		),
		(
			"inside html",
			b"<html><body><svg></svg></body></html>".to_vec(),
		),
		("past the first kib", padded.into_bytes()),
		("utf-16le with mark", utf16("<svg/>", true, true)),
		("utf-16be with mark", utf16("<svg/>", false, true)),
		("utf-16le without mark", utf16("<svg/>", true, false)),
		("utf-16be without mark", utf16("<svg/>", false, false)),
	] {
		assert!(is_svg(&bytes), "{case}");
	}
}

#[test]
fn text_that_only_mentions_svg_is_not_svg() {
	assert!(!is_svg(b"see the attached svg file, or <svgfont>"));
	assert!(!is_svg(&corpus::png()));
	let late = format!("{}<svg/>", " ".repeat(SVG_WINDOW));
	assert!(!is_svg(late.as_bytes()), "past the window");
}

#[test]
fn gzip_is_opened_to_find_the_element() {
	assert!(gunzip(&gzip(b"<svg/>")).is_some_and(|plain| is_svg(&plain)));
	assert_eq!(gunzip(b"not gzip"), None);
}
