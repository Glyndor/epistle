use super::*;

const HOST: &str = "mail.example.org";

#[test]
fn local_and_unparseable_authserv_ids_are_removed() {
	for value in [
		"mail.example.org; spf=pass",
		"MAIL.EXAMPLE.ORG; none",
		"mail.example.org.; none",
		"(prior (nested)) mail.example.org (note) 1; none",
		"\r\n\tmail.example.org;\r\n\tspf=pass",
		"\"mail.example.org\"; none",
		"\"mail\\.example.org\"; none",
		"",
		"; spf=pass",
		"other.example missing-separator",
		"other.example invalid-version; none",
		"other.example 1x; none",
		"(unclosed other.example; none",
		"other.example (unclosed; none",
		"\"unclosed; none",
		"\"other.example\"junk; none",
		"other@example; none",
		"\u{fffd}; none",
	] {
		let mut data =
			format!("Authentication-Results: {value}\r\nSubject: kept\r\n\r\nbody").into_bytes();
		strip(&mut data, HOST);
		assert_eq!(data, b"Subject: kept\r\n\r\nbody", "{value:?}");
	}
}

#[test]
fn other_parseable_authserv_ids_are_kept_byte_for_byte() {
	for value in [
		"other.example; spf=pass",
		"other.example 1; none",
		"mail.example.org.evil; none",
		"(comment) other.example (nested (comment)) 12; none",
		"\r\n\tother.example;\r\n\tdkim=pass",
		"\"other.example\"; none",
		"\"other\\.example\"; none",
		"\"other;example\"; none",
		"\"other\r\n\tservice\"; none",
	] {
		let original = format!("Authentication-Results: {value}\r\n\r\nbody").into_bytes();
		let mut data = original.clone();
		strip(&mut data, HOST);
		assert_eq!(data, original, "{value:?}");
	}
}

#[test]
fn trust_headers_and_their_continuations_are_removed_case_insensitively() {
	for name in [
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Flag",
		"X-Spam-Checker-Version",
		"X-Epistle-Attachment-Warning",
		"X-Epistle-Other",
	] {
		let mut data = format!(
			"{}: forged\r\n\tcontinued\r\nSubject: kept\r\n\r\n{name}: body\r\n",
			name.to_ascii_lowercase()
		)
		.into_bytes();
		let ptr = data.as_ptr();
		let capacity = data.capacity();
		strip(&mut data, HOST);
		assert_eq!(
			data,
			format!("Subject: kept\r\n\r\n{name}: body\r\n").as_bytes()
		);
		assert_eq!(data.as_ptr(), ptr);
		assert_eq!(data.capacity(), capacity);
	}
}

#[test]
fn signatures_trace_unrelated_fields_and_binary_body_are_untouched() {
	let kept = b"Received: from prior.example\r\nDKIM-Signature: original\r\n\tfold\r\nARC-Seal: original\r\nARC-Message-Signature: original\r\nARC-Authentication-Results: i=1; other.example; none\r\nBcc: retained\r\nX-Custom: kept\r\nX-Spam: kept\r\n\r\n\xff\0X-Spam-Status: body\r\n";
	let mut data = b"X-Spam-Status: forged\r\n".to_vec();
	data.extend_from_slice(kept);
	strip(&mut data, HOST);
	assert_eq!(data, kept);
}

#[test]
fn repeated_fields_are_compacted_without_reallocating_or_changing_the_body() {
	for count in [50, 9_800] {
		let mut data = "Authentication-Results: mail.example.org; spf=pass\r\n\tfolded\r\n"
			.repeat(count)
			.into_bytes();
		data.extend_from_slice(b"Subject: kept\r\n\r\n");
		data.extend(std::iter::repeat_n(0xff, 1024 * 1024));
		let ptr = data.as_ptr();
		strip(&mut data, HOST);
		assert_eq!(data.as_ptr(), ptr);
		assert!(data.starts_with(b"Subject: kept\r\n\r\n"));
		assert_eq!(data.len(), b"Subject: kept\r\n\r\n".len() + 1024 * 1024);
		assert!(
			data[b"Subject: kept\r\n\r\n".len()..]
				.iter()
				.all(|b| *b == 0xff)
		);
	}
}

#[test]
fn empty_header_only_and_lf_messages_have_the_same_policy() {
	for (input, expected) in [
		(b"".as_slice(), b"".as_slice()),
		(b"\r\nX-Spam-Status: body", b"\r\nX-Spam-Status: body"),
		(b"Return-Path: forged", b""),
		(
			b"X-Spam-Score: forged\nSubject: kept\n\nbody",
			b"Subject: kept\n\nbody",
		),
		(
			b"Authentication-Results: \xff; none\r\n\r\nbody",
			b"\r\nbody",
		),
	] {
		let mut data = input.to_vec();
		strip(&mut data, HOST);
		assert_eq!(data, expected);
	}
}
