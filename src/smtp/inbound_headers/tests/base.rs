use super::*;

const HOST: &str = "mail.example.org";

/// Every alias made by inserting a whitespace/control byte must still be
/// removed for permissive clients. Do not skip vectors merely because the
/// strict 1.0 parser no longer recognises their canonical names. Check the
/// complete retained buffer, including non-text body octets.
#[test]
fn obfuscated_reserved_names_are_removed_before_permissive_readers() {
	let parser = mail_parser::MessageParser::default();
	for name in [
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
		"X-Epistle",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Future",
		"X-Epistle-Attachment-Warning",
		"X-Epistle-Future",
	] {
		for at in 0..=name.len() {
			for byte in [b' ', b'\t', 0x0c, 0x0b, 0x1f, 0x7f] {
				let alias = format!("{}{}{}", &name[..at], char::from(byte), &name[at..]);
				let original = format!(
					"{alias}: {HOST}; dkim=pass\r\n\tcontinued\r\nSubject: kept\r\n\r\nbody"
				)
				.into_bytes();
				let mut data = original.clone();
				data.extend_from_slice(b"\0\xff");
				strip(&mut data, HOST);
				assert_eq!(data, b"Subject: kept\r\n\r\nbody\0\xff", "{alias:?}");
				let parsed = parser.parse(&data).expect("message");
				assert!(parsed.headers().value(name).is_none(), "{alias:?}");
			}
		}
	}
}

#[test]
fn accepted_hostname_is_canonical_for_comparison_and_emission() {
	for hostname in [
		" mail.example.org ",
		"MAIL.EXAMPLE.ORG",
		" Mail.Example.Org. ",
	] {
		let raw = format!(
			r#"
hostname = "{hostname}"
data_dir = "/var/lib/mail"
domains = ["example.org"]
[[accounts]]
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#
		);
		let config = crate::config::Config::parse_text(&raw, std::path::Path::new("mail.toml"))
			.expect("accepted configuration");
		let mut data =
			format!("Authentication-Results: {HOST}; dkim=pass\r\n\r\nbody").into_bytes();
		strip(&mut data, &config.hostname);
		assert_eq!(data, b"\r\nbody", "{hostname:?}");
		assert_eq!(config.hostname, HOST);
		assert_eq!(
			crate::smtp::trace::format_auth_results(&config.hostname, &["dkim=none".into()]),
			format!("Authentication-Results: {HOST};\r\n\tdkim=none\r\n")
		);
	}
}

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
		let field_len = b"Authentication-Results: mail.example.org; spf=pass\r\n\tfolded\r\n".len();
		data.extend_from_slice(b"Subject: kept\r\n\r\n");
		let body = std::iter::repeat_n(0xff, 1024 * 1024).collect::<Vec<u8>>();
		data.extend_from_slice(&body);
		let ptr = data.as_ptr();
		// Reset the bytes-moved counter so this test owns the assertion
		// for the compaction cost. The linear in-place pass moves each
		// kept field once and the body once, so the total is at most
		// `(kept_field_count) * field_len + body_len`. A regression to
		// per-field `Vec::drain` would move the suffix once per removed
		// field (quadratic in `count * field_len`), which blows past the
		// bound by orders of magnitude. The bound leaves room for one
		// move of every kept field plus one move of the body, with a
		// generous margin for the test harness.
		reset_moves();
		strip(&mut data, HOST);
		assert_eq!(data.as_ptr(), ptr);
		assert!(data.starts_with(b"Subject: kept\r\n\r\n"));
		assert_eq!(data.len(), b"Subject: kept\r\n\r\n".len() + body.len());
		assert!(
			data[b"Subject: kept\r\n\r\n".len()..]
				.iter()
				.all(|b| *b == 0xff)
		);
		let linear_bound = 2 * (field_len + b"Subject: kept\r\n\r\n".len() + body.len());
		let moved = moves();
		assert!(
			moved <= linear_bound,
			"moves {moved} exceeds linear bound {linear_bound} for count={count}"
		);
	}
}

/// `strip_with_drain_for_test` swaps the in-place compaction for one
/// `Vec::drain` per removed field. The result and the buffer pointer
/// are the same; only the work is quadratic. The compaction test above
/// MUST fail under this swap, otherwise it does not really bound the
/// cost and a regression to the drain form would not be caught.
#[test]
fn the_linear_per_field_swap_is_caught_by_the_compaction_cost_test() {
	let count = 9_800;
	let mut data = "Authentication-Results: mail.example.org; spf=pass\r\n\tfolded\r\n"
		.repeat(count)
		.into_bytes();
	data.extend_from_slice(b"Subject: kept\r\n\r\n");
	let body = std::iter::repeat_n(0xff, 1024 * 1024).collect::<Vec<u8>>();
	data.extend_from_slice(&body);
	let field_len = b"Authentication-Results: mail.example.org; spf=pass\r\n\tfolded\r\n".len();
	let linear_bound = 2 * (field_len + b"Subject: kept\r\n\r\n".len() + body.len());
	reset_moves();
	strip_with_drain_for_test(&mut data, HOST);
	let moved = moves();
	assert!(
		moved > linear_bound,
		"drain swap moved only {moved} bytes; expected quadratic over linear bound {linear_bound}"
	);
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

/// Leading `:` and ASCII whitespace at the start of the line are folded by
/// mail-parser 0.11.9
/// (`mail-parser/src/parsers/header.rs::parse_header_name`); the stripper
/// mirrors that byte rule so the canonical-name comparison sees
/// the same effective name every downstream reader does. Without this,
/// `:Authentication-Results: mail.example.org; dkim=pass` parsed to an
/// empty name and survived strip as a forged trust field.
#[test]
fn leading_colon_aliases_are_removed_with_the_strict_reader() {
	for name in [
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Epistle-Attachment-Warning",
	] {
		for prefix in [
			":",
			"::",
			":::",
			": ",
			" :",
			"\t:",
			":\t",
			":\t:",
			" : ",
			"\t :\t:\t",
		] {
			let value = if name == "Authentication-Results" {
				format!("{HOST}; dkim=pass; forged")
			} else {
				"forged".to_string()
			};
			let original =
				format!("{prefix}{name}: {value}\r\nSubject: kept\r\n\r\nbody").into_bytes();
			// The new parser keeps a colon-prefixed alias distinct. The
			// stripper must still remove the exact forged bytes for clients
			// that use the older, permissive reading.
			let pre = mail_parser::MessageParser::default()
				.parse(&original)
				.expect("original parses");
			assert!(pre.headers().value(name).is_none(), "{prefix:?}{name:?}");
			assert!(
				String::from_utf8_lossy(&original).contains(&format!("{prefix}{name}: {value}"))
			);
			let mut data = original.clone();
			strip(&mut data, HOST);
			assert_eq!(data, b"Subject: kept\r\n\r\nbody", "{prefix:?}{name:?}");
			let post = mail_parser::MessageParser::default()
				.parse(&data)
				.expect("stripped parses");
			assert!(
				post.headers().value(name).is_none(),
				"mail-parser must not see it after strip: {prefix:?}{name:?}"
			);
		}
	}
}

/// Lines made up of nothing but folded leader bytes (`:` and whitespace)
/// have no header at all per mail-parser; strip leaves them in place.
#[test]
fn leader_only_lines_are_kept_without_a_name() {
	for prefix in [":", "::", ": \t:", "::::::", "   \t  "] {
		let input = format!("{prefix}\r\nSubject: kept\r\n\r\nbody").into_bytes();
		let pre = mail_parser::MessageParser::default()
			.parse(&input)
			.expect("parses");
		assert!(
			pre.headers().value("Authentication-Results").is_none(),
			"{prefix:?}"
		);
		let mut data = input.clone();
		strip(&mut data, HOST);
		assert_eq!(data, input, "{prefix:?}");
		assert!(reserved_remaining(&data, HOST).is_none(), "{prefix:?}");
	}
}

mod safety_net;
