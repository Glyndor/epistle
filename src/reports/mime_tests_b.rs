use super::*;

#[test]
fn uncompressed_payload_limit_is_enforced() {
	for headers in [
		"Content-Type: application/tlsrpt+json",
		"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=report.json",
	] {
		let mut raw = format!("{headers}\r\n\r\n").into_bytes();
		raw.extend(vec![b' '; MAX_COMPRESSED]);
		let found = find_report_part(&raw, Kind::TlsRpt).expect("at payload cap");
		assert_eq!(found.bytes.len(), MAX_COMPRESSED);
		raw.push(b' ');
		assert!(matches!(
			find_report_part(&raw, Kind::TlsRpt),
			Err(WalkError::TooLarge)
		));
	}
}

#[test]
fn folded_top_level_boundary_keeps_the_following_header() {
	let raw = b"Content-Type: multipart/mixed;\r\n boundary=BOUND\r\nMIME-Version: 1.0\r\n\r\n--BOUND\r\nContent-Type: application/gzip\r\n\r\npayload\r\n--BOUND--\r\n";
	let found = find_report_part(raw, Kind::Dmarc).expect("folded boundary");
	assert_eq!(found.bytes, b"payload");
}

#[test]
fn folded_part_headers_preserve_filename_and_transfer_encoding() {
	let raw = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n--BOUND\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment;\r\n\tfilename=report.xml.gz\r\nContent-Transfer-Encoding:\r\n base64\r\nX-Trailer: separate\r\n\r\ncGF5bG9hZA==\r\n--BOUND--\r\n";
	let found = find_report_part(raw, Kind::Dmarc).expect("folded attachment headers");
	assert_eq!(found.encoding, Encoding::Gzip);
	assert_eq!(found.bytes, b"payload");
}

#[test]
fn lf_top_level_empty_body_is_preserved() {
	let found = find_report_part(b"Content-Type: application/gzip\n\n", Kind::Dmarc)
		.expect("empty LF body");
	assert!(found.bytes.is_empty());
}

#[test]
fn lf_top_level_payload_is_preserved() {
	let raw = b"Content-Type: application/gzip\nContent-Transfer-Encoding: base64\n\ncGF5bG9hZA==";
	let found = find_report_part(raw, Kind::Dmarc).expect("LF body");
	assert_eq!(found.bytes, b"payload");
}

#[test]
fn lf_part_empty_body_is_preserved() {
	let raw = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n--BOUND\nContent-Type: application/gzip\n\n\n--BOUND--\n";
	let found = find_report_part(raw, Kind::Dmarc).expect("empty LF part body");
	assert!(found.bytes.is_empty());
}

#[test]
fn lf_part_payload_is_preserved() {
	let raw = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n--BOUND\nContent-Type: application/gzip\nContent-Transfer-Encoding: base64\n\ncGF5bG9hZA==\n--BOUND--\n";
	let found = find_report_part(raw, Kind::Dmarc).expect("LF part body");
	assert_eq!(found.bytes, b"payload");
}

fn multipart(part: &str, boundary: &str, newline: &str) -> String {
	format!(
		"Content-Type: multipart/mixed; boundary={boundary}{newline}{newline}--{boundary}{newline}{part}--{boundary}--{newline}"
	)
}

#[test]
fn empty_sections_are_refused_at_each_supported_depth() {
	for newline in ["\r\n", "\n"] {
		for depth in 1..=MAX_NESTING_DEPTH {
			for empty in [String::new(), newline.to_string()] {
				let mut raw = multipart(&empty, "BOUND", newline);
				for level in 1..depth {
					raw = multipart(&raw, &format!("OUTER{level}"), newline);
				}
				let err = find_report_part(raw.as_bytes(), Kind::Dmarc)
					.expect_err("empty section refused");
				assert!(matches!(err, WalkError::Malformed("part has no headers")));
			}
			let part = format!("Content-Type: application/gzip{newline}{newline}x{newline}");
			let mut raw = multipart(&part, "BOUND", newline);
			for level in 1..depth {
				raw = multipart(&raw, &format!("OUTER{level}"), newline);
			}
			let found = find_report_part(raw.as_bytes(), Kind::Dmarc).expect("nonempty part");
			assert_eq!(found.bytes, b"x");
		}
	}
}
