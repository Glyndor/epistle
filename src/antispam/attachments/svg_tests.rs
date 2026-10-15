use std::io::Write as _;

use super::*;
use crate::antispam::attachments::corpus;

pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(bytes).expect("gzip");
	encoder.finish().expect("gzip")
}

pub(crate) fn utf16le(text: &str) -> Vec<u8> {
	let mut out = b"\xff\xfe".to_vec();
	out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
	out
}

#[test]
fn an_svg_is_recognised_by_its_root_element() {
	assert!(is_svg(b"\xef\xbb\xbf  <?xml version=\"1.0\"?><svg/>"));
	assert!(is_svg(
		b"<!-- logo -->\n<SVG xmlns=\"http://www.w3.org/2000/svg\"/>"
	));
	assert!(is_svg(b"<x:svg xmlns:x=\"http://www.w3.org/2000/svg\"/>"));
	let padded = format!("<!--{}--><!DOCTYPE svg><svg/>", "c".repeat(4000));
	assert!(is_svg(padded.as_bytes()), "comments past the first KiB");
	assert!(is_svg(&utf16le("<svg onload='x'/>")));
	assert!(!is_svg(b"<html><body><svg/></body></html>"));
	assert!(!is_svg(b"just text"));
	assert!(!is_svg(&corpus::png()));
}

#[test]
fn active_svg_content_is_found_in_any_spelling() {
	for svg in [
		&b"<svg><script>alert(1)</script></svg>"[..],
		b"<svg><SCRIPT href=x.js/></svg>",
		b"<x:svg xmlns:x='http://www.w3.org/2000/svg'><x:script>go()</x:script></x:svg>",
		b"<svg><script><![CDATA[go()]]></script></svg>",
		b"<svg onload=\"go()\"/>",
		b"<svg><rect ONCLICK = 'go()'/></svg>",
		b"<svg><rect o&#110;mouseover=\"go()\"/></svg>",
		b"<svg><a href=\"java\tscript:go()\">x</a></svg>",
		b"<svg><a href=\"&#x6a;avascript:go()\">x</a></svg>",
		b"<svg><a xlink:href=\"javascript&colon;go()\">x</a></svg>",
		b"<svg><use xlink:href=\"data:text/html;base64,PHNjcmlwdD4=\"/></svg>",
		b"<svg><foreignObject><body/></foreignObject></svg>",
		b"<svg><iframe src=x/></svg>",
		b"<svg><embed src=x/></svg>",
		b"<svg><object data=x/></svg>",
		b"<svg><handler type='text/ecmascript'>go()</handler></svg>",
	] {
		assert_eq!(
			inspect_svg(svg),
			SvgVerdict::Active,
			"{}",
			String::from_utf8_lossy(svg)
		);
	}
	assert_eq!(
		inspect_svg(&utf16le("<svg><script>go()</script></svg>")),
		SvgVerdict::Active
	);
}

#[test]
fn entity_declarations_make_an_svg_ambiguous() {
	let svg = b"<!DOCTYPE svg [<!ENTITY a \"&#106;avascript:\">]><svg><a href='&a;go()'/></svg>";
	assert_eq!(inspect_svg(svg), SvgVerdict::Ambiguous);
}

#[test]
fn a_plain_svg_is_clean() {
	let svg = b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" \
		width=\"10\" height=\"10\"><rect fill=\"#000\" data-on=\"x\"/></svg>";
	assert_eq!(inspect_svg(svg), SvgVerdict::Clean);
}

#[test]
fn an_svg_too_long_to_read_counts_as_active() {
	let mut svg = b"<svg>".to_vec();
	svg.resize(SVG_SCAN_BYTES + 1, b' ');
	assert_eq!(inspect_svg(&svg), SvgVerdict::Active);
}

#[test]
fn gzip_is_opened_and_broken_gzip_is_refused() {
	let svgz = gzip(b"<svg onload='go()'/>");
	assert_eq!(
		gunzip(&svgz).map(|plain| inspect_svg(&plain)),
		Some(SvgVerdict::Active)
	);
	assert_eq!(gunzip(b"\x1f\x8b\x08 not really gzip"), None);
}
