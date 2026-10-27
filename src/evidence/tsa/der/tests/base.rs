use super::*;

#[test]
fn encoded_elements_read_back() {
	for length in [0usize, 1, 127, 128, 255, 256, 70_000] {
		let content = vec![7u8; length];
		let bytes = encode(tag::OCTET_STRING, &content);
		let tlv = parse_one(&bytes, tag::OCTET_STRING).expect("parse");
		assert_eq!(tlv.value.len(), length);
		assert_eq!(tlv.raw.len(), bytes.len());
	}
}

#[test]
fn lengths_must_be_definite_minimal_and_inside_the_input() {
	let cases: [(&[u8], DerError); 7] = [
		(&[0x04, 0x80], DerError::BadLength),
		(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5], DerError::BadLength),
		(&[0x04, 0x82, 0x00, 0x80], DerError::BadLength),
		(&[0x04, 0x85, 1, 0, 0, 0, 0], DerError::BadLength),
		(&[0x04, 0x84, 0x7f, 0xff, 0xff, 0xff], DerError::Truncated),
		(&[0x04, 0x03, 1, 2], DerError::Truncated),
		(&[0x1f, 0x01, 0x00], DerError::HighTag),
	];
	for (bytes, expected) in cases {
		assert_eq!(parse_one(bytes, bytes[0]), Err(expected), "{bytes:02x?}");
	}
	assert_eq!(
		parse_one(&[0x04, 0x00, 0x00], 0x04),
		Err(DerError::Trailing)
	);
	assert_eq!(
		parse_one(&[0x02, 0x00], 0x04),
		Err(DerError::Unexpected(0x02))
	);
	assert_eq!(parse_one(&[], 0x04), Err(DerError::Truncated));
}

#[test]
fn optional_elements_consume_only_their_tag() {
	let bytes = [encode(tag::INTEGER, &[1]), encode(tag::BOOLEAN, &[0xff])].concat();
	let mut reader = Reader::new(&bytes);
	assert_eq!(reader.optional(tag::BOOLEAN), Ok(None));
	assert!(reader.optional(tag::INTEGER).expect("int").is_some());
	assert!(reader.optional(tag::BOOLEAN).expect("bool").is_some());
	assert!(reader.is_empty());
}

#[test]
fn integers_are_minimal_non_negative_and_bounded() {
	for value in [0u64, 1, 127, 128, 255, 256, u64::MAX] {
		let bytes = encode(tag::INTEGER, &unsigned_content(value));
		let tlv = parse_one(&bytes, tag::INTEGER).expect("parse");
		assert_eq!(small_unsigned(&tlv), Ok(value));
	}
	for bad in [
		&[][..],
		&[0x80],
		&[0x00, 0x01],
		&[1, 2, 3, 4, 5, 6, 7, 8, 9],
	] {
		let bytes = encode(tag::INTEGER, bad);
		let tlv = parse_one(&bytes, tag::INTEGER).expect("parse");
		assert_eq!(small_unsigned(&tlv), Err(DerError::BadValue), "{bad:02x?}");
	}
}

#[test]
fn generalized_time_reads_utc_seconds() {
	let at = |text: &str| {
		let bytes = encode(tag::GENERALIZED_TIME, text.as_bytes());
		generalized_time(&parse_one(&bytes, tag::GENERALIZED_TIME).expect("parse"))
	};
	assert_eq!(at("19700101000000Z"), Ok(0));
	assert_eq!(at("20261015043151Z"), Ok(1_792_038_711));
	assert_eq!(at("20261015043151.123Z"), Ok(1_792_038_711));
	for bad in [
		"20261015043151",
		"20261015043151+0000",
		"20261315043151Z",
		"2026101504315Z",
		"20261015043151.Z",
		"20261015253151Z",
	] {
		assert_eq!(at(bad), Err(DerError::BadValue), "{bad}");
	}
}
