use super::*;
use crate::antispam::attachments::corpus;

#[test]
fn an_svg_is_recognised_whatever_it_is_called() {
	assert!(is_svg(b"\xef\xbb\xbf  <?xml version=\"1.0\"?><svg/>"));
	assert!(is_svg(
		b"<!-- logo -->\n<SVG xmlns=\"http://www.w3.org/2000/svg\"/>"
	));
	assert!(!is_svg(b"just text"));
	assert!(!is_svg(&corpus::png()));
}

#[test]
fn active_svg_content_is_found_in_any_spelling() {
	for svg in [
		&b"<svg><script>alert(1)</script></svg>"[..],
		b"<svg><SCRIPT href=x.js/></svg>",
		b"<svg onload=\"go()\"/>",
		b"<svg><rect ONCLICK = 'go()'/></svg>",
		b"<svg><rect o&#110;mouseover=\"go()\"/></svg>",
		b"<svg><a href=\"java\tscript:go()\">x</a></svg>",
		b"<svg><a href=\"&#x6a;avascript:go()\">x</a></svg>",
		b"<svg><image href=\"data:text/html;base64,PHNjcmlwdD4=\"/></svg>",
		b"<svg><foreignObject><body/></foreignObject></svg>",
		b"<svg><iframe src=x/></svg>",
		b"<svg><embed src=x/></svg>",
		b"<svg><object data=x/></svg>",
	] {
		assert!(svg_is_active(svg), "{}", String::from_utf8_lossy(svg));
	}
}

#[test]
fn a_plain_svg_is_not_active() {
	let svg = b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" \
		width=\"10\" height=\"10\"><rect fill=\"#000\" data-on=\"x\"/></svg>";
	assert!(!svg_is_active(svg));
}

#[test]
fn an_svg_too_long_to_read_counts_as_active() {
	let mut svg = b"<svg>".to_vec();
	svg.resize(SVG_SCAN_BYTES + 1, b' ');
	assert!(svg_is_active(&svg));
}

pub(crate) fn pe_header() -> Vec<u8> {
	let mut pe = b"MZ".to_vec();
	pe.resize(0x3c, 0);
	pe.extend_from_slice(&0x40u32.to_le_bytes());
	pe.extend_from_slice(b"PE\0\0");
	pe
}

pub(crate) fn png_then(tail: &[u8]) -> Vec<u8> {
	let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
	png.extend_from_slice(&13u32.to_be_bytes());
	png.extend_from_slice(b"IHDR");
	png.extend_from_slice(&[0; 13 + 4]);
	png.extend_from_slice(&0u32.to_be_bytes());
	png.extend_from_slice(b"IEND");
	png.extend_from_slice(&[0; 4]);
	png.extend_from_slice(tail);
	png
}

pub(crate) fn jpeg_then(tail: &[u8]) -> Vec<u8> {
	let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
	jpeg.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
	jpeg.extend_from_slice(&[0xff, 0xda, 0x00, 0x08, 1, 2, 3, 4, 5, 6]);
	jpeg.extend_from_slice(&[0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56]);
	jpeg.extend_from_slice(&[0xff, 0xd9]);
	jpeg.extend_from_slice(tail);
	jpeg
}

pub(crate) fn gif_then(tail: &[u8]) -> Vec<u8> {
	let mut gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
	gif.extend_from_slice(&[0x21, 0xf9, 0x04, 0, 0, 0, 0, 0x00]);
	gif.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0x00]);
	gif.extend_from_slice(&[0x02, 0x02, 0x4c, 0x01, 0x00]);
	gif.push(0x3b);
	gif.extend_from_slice(tail);
	gif
}

pub(crate) fn webp_then(tail: &[u8]) -> Vec<u8> {
	let mut webp = b"RIFF".to_vec();
	webp.extend_from_slice(&12u32.to_le_bytes());
	webp.extend_from_slice(b"WEBPVP8 \0\0\0\0");
	webp.extend_from_slice(tail);
	webp
}

#[test]
fn a_payload_after_the_logical_end_of_an_image_is_found() {
	let cases: Vec<(RealType, Vec<u8>)> = vec![
		(RealType::Png, png_then(&pe_header())),
		(RealType::Jpeg, jpeg_then(&corpus::zip_of(&["a.txt"]))),
		(RealType::Gif, gif_then(b"\x7fELF\x02\x01\x01")),
		(RealType::Webp, webp_then(b"#!/bin/sh\nrm -rf ~\n")),
	];
	for (real, bytes) in cases {
		assert!(has_appended_payload(real, &bytes), "{real:?}");
	}
}

#[test]
fn a_clean_image_or_harmless_trailing_bytes_are_not_a_payload() {
	let cases: Vec<(RealType, Vec<u8>)> = vec![
		(RealType::Png, png_then(b"")),
		(RealType::Png, png_then(b"MZ but no PE header")),
		(RealType::Jpeg, jpeg_then(b"\0\0")),
		(RealType::Gif, gif_then(b"")),
		(RealType::Webp, webp_then(b"")),
	];
	for (real, bytes) in cases {
		assert!(!has_appended_payload(real, &bytes), "{real:?}");
	}
}

#[test]
fn the_tail_scan_stays_linear() {
	let tail = b"MZ".repeat(4 << 20);
	let started = std::time::Instant::now();
	assert!(!has_appended_payload(RealType::Png, &png_then(&tail)));
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
