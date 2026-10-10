use super::{addresses, protect, render};

#[test]
fn growing_marker_header_has_bounded_protected_length() {
	const SIZE: usize = 256 * 1024;
	let suffix = b"\" <local@example.test>";
	let mut raw = vec![b'"'];
	for run in 0.. {
		if raw.len() + b"IMAPRAW".len() + run + 1 > SIZE / 2 {
			break;
		}
		raw.extend_from_slice(b"IMAPRAW");
		raw.extend(std::iter::repeat_n(b'X', run));
		raw.push(b' ');
	}
	while raw.len() + suffix.len() + 3 <= SIZE {
		raw.extend_from_slice(b"\xff=?");
	}
	raw.resize(SIZE - suffix.len(), b'X');
	raw.extend_from_slice(suffix);
	assert_eq!(raw.len(), SIZE, "address fixture must contain 256 KiB");
	let protected = protect(&raw);
	assert!(
		protected.len() <= 3 * raw.len(),
		"address protection must use at most three bytes per input byte"
	);
	let name = &raw[1..raw.len() - suffix.len()];
	let mut expected = format!("(({{{}}}\r\n", name.len()).into_bytes();
	expected.extend_from_slice(name);
	expected.extend_from_slice(b" NIL \"local\" \"example.test\"))");
	assert!(
		addresses(Some(&raw)) == expected,
		"large address headers must preserve the exact display name and mailbox"
	);
}

#[test]
fn envelope_preserves_every_non_ascii_octet() {
	let name: Vec<u8> = (128..=255).cycle().take(16 * 1024).collect();
	let mut raw = b"From: \"".to_vec();
	raw.extend_from_slice(&name);
	raw.extend_from_slice(b"\" <local@example.test>\r\n\r\nx");
	let parsed = super::super::parse(&raw);
	let mut address = format!("(({{{}}}\r\n", name.len()).into_bytes();
	address.extend_from_slice(&name);
	address.extend_from_slice(b" NIL \"local\" \"example.test\"))");
	let mut expected = b"(NIL NIL ".to_vec();
	for i in 0..3 {
		if i != 0 {
			expected.push(b' ');
		}
		expected.extend_from_slice(&address);
	}
	expected.extend_from_slice(b" NIL NIL NIL NIL NIL)");
	assert!(
		render(&parsed, 0) == expected,
		"ENVELOPE must preserve every non-ASCII display-name octet exactly"
	);
}

#[test]
fn private_use_input_cannot_collide_with_protection() {
	let name = "\u{f780}\u{f7ff}\u{f800} =?UTF-8?Q?caf=C3=A9?=";
	let raw = format!("\"{name}\" <\u{f780}@\u{f800}.test>");
	let mut expected = format!("(({{{}}}\r\n{name} NIL {{3}}\r\n", name.len()).into_bytes();
	expected.extend_from_slice("\u{f780} {8}\r\n\u{f800}.test))".as_bytes());
	assert!(
		addresses(Some(raw.as_bytes())) == expected,
		"private-use input and encoded words must retain their original bytes"
	);
}
