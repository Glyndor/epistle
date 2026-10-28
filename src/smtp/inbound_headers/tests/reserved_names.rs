use super::*;

const HOST: &str = "mail.example.org";

// Tests in this file cover the gaps a second correctness review
// (2026-10-15) flagged about the union of the three header-name readers:
// the byte-level strip pass, the safety net over the header block, and
// the parsers DKIM and ARC-AMS run on the bytes the strip produces.

/// RFC 5322 §3.6.8 limits field names to printable ASCII, so a non-ASCII
/// whitespace byte at the end of the name is already a malformed header.
/// The 19 non-ASCII whitespace characters of `char::is_whitespace` are
/// the only ones that match. Each one bypasses both mail-parser 0.11.9
/// (which preserves trailing non-ASCII whitespace in the name) and our
/// own strip pass (which only trims ASCII whitespace). DKIM and ARC-AMS
/// fold the same bytes with `name.trim_end()` and call the result the
/// canonical reserved name. The strip and the safety net must both close
/// the gap: the strip removes the field so the bytes the sink gets do
/// not carry a canonical reserved name, and the safety net reports one
/// when a strip with a hole leaves it.
#[test]
fn trailing_unicode_whitespace_does_not_let_a_reserved_field_through() {
	const NAMES: &[&str] = &[
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
	];
	// The 19 non-ASCII whitespace code points recognised by
	// `char::is_whitespace`. TAB, LF, CR, FF and SPACE are ASCII and are
	// already handled by the existing ASCII whitespace fold.
	const UNICODE_WS: &[char] = &[
		'\u{0085}', '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}',
		'\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}',
		'\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
	];
	let parser = mail_parser::MessageParser::default();
	let dkim_names = crate::dkim::header_names;
	let arc_names = crate::arc::header_names;
	for name in NAMES {
		for ws in UNICODE_WS {
			let value = if *name == "Authentication-Results" {
				format!("{HOST}; dkim=pass; forged")
			} else {
				"forged".to_string()
			};
			let raw = format!("{name}{ws}: {value}\r\nSubject: kept\r\n\r\nbody").into_bytes();
			// Pre-condition: the real DKIM and ARC-AMS parsers both read
			// the field as the canonical reserved name (this is the leak
			// the review found). If a future parser stopped folding
			// trailing Unicode whitespace the loop would only have to
			// prove the new fold is safe, not that the strip hides the
			// name.
			assert!(
				dkim_names(&raw).iter().any(|n| n == *name),
				"DKIM must read canonical {name:?} with trailing {ws:?}"
			);
			assert!(
				arc_names(&raw).iter().any(|n| n == *name),
				"ARC must read canonical {name:?} with trailing {ws:?}"
			);
			// mail-parser 0.11.9 keeps the trailing Unicode whitespace
			// in the name, so its `header(name)` lookup misses the
			// canonical form: this is the gap the safety net covers.
			let pre = parser.parse(&raw).expect("pre parses");
			assert_eq!(
				pre.header(*name),
				None,
				"mail-parser must keep the trailing {ws:?} on {name:?}"
			);
			// Strip must remove the field entirely so the bytes that
			// reach the sink do not carry the canonical reserved name.
			let mut data = raw.clone();
			strip(&mut data, HOST);
			assert_eq!(data, b"Subject: kept\r\n\r\nbody", "{name:?} {ws:?}");
			let post = parser.parse(&data).expect("post parses");
			assert!(post.header(*name).is_none(), "{name:?} {ws:?}");
			assert!(
				!dkim_names(&data).iter().any(|n| n == *name),
				"DKIM must not see {name:?} after strip ({ws:?})"
			);
			// Safety net: the union of readings is the contract the
			// second pass must hold. mail-parser keeps the trailing
			// Unicode whitespace in the name and reads no canonical
			// reserved field; the safety net must still flag it because
			// DKIM/ARC fold the same bytes with `name.trim_end()` and
			// call the result the canonical reserved name. We feed the
			// raw bytes to `reserved_remaining` without strip, since any
			// in-place strip already removes the field as soon as it
			// sees the Unicode whitespace.
			assert_eq!(
				reserved_remaining(&raw, HOST),
				Some(*name),
				"safety net must flag {name:?} with trailing {ws:?}"
			);
		}
	}
}

/// Field names that look like a reserved name with an extra `-` (mail-parser
/// keeps the distinct name, no other reader folds it) must survive the
/// strip pass. A stray `-` is not a foldable byte: it only maps to a `-`
/// at the same position in the canonical name. The pre-condition asserts
/// mail-parser sees the distinct name in the raw input, so a strip that
/// silently removed it could not pass the test by virtue of the input
/// never carrying the field.
#[test]
fn stray_dashes_in_field_names_are_not_stripped_as_obfuscation() {
	let parser = mail_parser::MessageParser::default();
	let cases: &[(&[u8], &str)] = &[
		(
			b"-Delivered-To: legitimate-extension\r\nSubject: hi\r\n\r\nbody",
			"-Delivered-To",
		),
		(
			b"Authentication--Results: prior.example; none\r\nSubject: hi\r\n\r\nbody",
			"Authentication--Results",
		),
	];
	for (raw, kept) in cases {
		let pre = parser.parse(&raw[..]).expect("pre parses");
		assert!(
			pre.header(*kept).is_some(),
			"mail-parser must keep the distinct name before strip: {kept}"
		);
		let mut data = raw.to_vec();
		strip(&mut data, HOST);
		assert_eq!(data.as_slice(), *raw, "{kept}");
		let post = parser.parse(&data).expect("post parses");
		assert!(
			post.header(*kept).is_some(),
			"strip must not remove the distinct name: {kept}"
		);
		assert!(
			reserved_remaining(&data, HOST).is_none(),
			"safety net must not flag a foreign field the readers cannot fold: {kept}"
		);
	}
}

/// Sanity baseline for the corrected rule: a reserved name with leading
/// whitespace or interior whitespace still folds to the canonical form.
/// The fold only applies when the canonical name has `-` at the same
/// position the name carries an obfuscation byte.
#[test]
fn reserved_names_with_interior_or_leading_whitespace_are_still_stripped() {
	for (raw, expected_header) in [
		(
			b" Delivered-To: forged\r\nSubject: kept\r\n\r\nbody".as_slice(),
			"Delivered-To",
		),
		(
			b"Received-SPF\t: forged\r\nSubject: kept\r\n\r\nbody",
			"Received-SPF",
		),
		(
			b"X-Spam- Status: forged\r\nSubject: kept\r\n\r\nbody".as_slice(),
			"X-Spam-Status",
		),
		(
			b"Authentication-Results : mail.example.org; dkim=pass\r\nSubject: kept\r\n\r\nbody"
				.as_slice(),
			"Authentication-Results",
		),
	] {
		let mut data = raw.to_vec();
		strip(&mut data, HOST);
		assert_eq!(data, b"Subject: kept\r\n\r\nbody", "{expected_header}");
		assert!(
			reserved_remaining(&data, HOST).is_none(),
			"{expected_header}"
		);
	}
}
