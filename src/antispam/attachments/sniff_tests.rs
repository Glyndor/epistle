use super::*;
use crate::antispam::attachments::corpus;

#[test]
fn every_signature_in_the_table_is_recognised() {
	let cases: &[(&[u8], RealType)] = &[
		(b"MZ\x90\x00", RealType::Pe),
		(b"\x7fELF\x02\x01", RealType::Elf),
		(b"\xcf\xfa\xed\xfe\x07\x00", RealType::MachO),
		(b"\xca\xfe\xba\xbe\x00\x00", RealType::MachO),
		(
			b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x9b",
			RealType::Lnk,
		),
		(b"#!/bin/sh\n", RealType::Script),
		(b"PK\x03\x04\x14\x00", RealType::Zip),
		(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00", RealType::Ole2),
		(b"%PDF-1.4\n", RealType::Pdf),
		(b"\x89PNG\r\n\x1a\n\x00", RealType::Png),
		(b"\xff\xd8\xff\xe0\x00\x10JFIF", RealType::Jpeg),
		(b"GIF89a\x01\x00", RealType::Gif),
		(b"RIFF\x00\x00\x00\x00WEBPVP8 ", RealType::Webp),
		(b"Rar!\x1a\x07\x01\x00", RealType::Rar),
		(b"7z\xbc\xaf\x27\x1c\x00\x04", RealType::SevenZip),
		(b"<!DOCTYPE html><html>", RealType::Html),
		(b"hello, plain text", RealType::Unknown),
	];
	for (bytes, expected) in cases {
		assert_eq!(sniff(bytes), *expected, "sniffing {expected:?}");
	}
}

#[test]
fn a_pdf_with_leading_junk_is_still_a_pdf() {
	let mut bytes = vec![b' '; 300];
	bytes.extend_from_slice(&corpus::pdf());
	assert_eq!(sniff(&bytes), RealType::Pdf);
}

#[test]
fn an_iso_image_is_found_at_its_volume_descriptor() {
	let mut bytes = vec![0u8; 0x8001];
	bytes.extend_from_slice(b"CD001\x01");
	assert_eq!(sniff(&bytes), RealType::Iso);
	assert!(bytes.len() <= SNIFF_WINDOW + 1);
}

#[test]
fn html_after_a_bom_and_whitespace_is_html_in_any_case() {
	assert_eq!(sniff(b"\xef\xbb\xbf\r\n  <HtMl><body>"), RealType::Html);
	assert_eq!(sniff(b"\n<form action=x>"), RealType::Html);
}

#[test]
fn executable_and_image_families_are_what_the_rules_rely_on() {
	for kind in [
		RealType::Pe,
		RealType::Elf,
		RealType::MachO,
		RealType::Lnk,
		RealType::Script,
	] {
		assert!(kind.is_executable(), "{kind:?} must count as executable");
	}
	assert!(!RealType::Zip.is_executable());
	assert!(RealType::Webp.is_image());
	assert!(!RealType::Pdf.is_image());
	assert_eq!(RealType::SevenZip.as_str(), "7z");
}

#[test]
fn bmp_tiff_ico_and_heif_are_images_and_text_is_not() {
	let mut bmp = b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00".to_vec();
	bmp.resize(64, 0);
	assert_eq!(sniff(&bmp), RealType::Bmp);
	assert_eq!(sniff(b"II*\x00\x08\x00"), RealType::Tiff);
	assert_eq!(sniff(b"\x00\x00\x01\x00\x01\x00\x10\x10"), RealType::Ico);
	assert_eq!(sniff(b"\x00\x00\x00\x18ftypheic\x00\x00"), RealType::Heif);
	assert_eq!(
		sniff(b"BMW meeting notes, nothing binary"),
		RealType::Unknown
	);
	for kind in [RealType::Bmp, RealType::Tiff, RealType::Ico, RealType::Heif] {
		assert!(kind.is_image() && kind.is_binary(), "{kind:?}");
	}
	assert!(!RealType::Script.is_binary());
}
