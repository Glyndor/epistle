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

/// The safety net re-parses with mail-parser and reports any reserved
/// field strip missed. It exists so a future mail-parser change that
/// folds a byte strip does not anticipate does not turn into a forged
/// header delivered.
#[test]
fn safety_net_flags_a_reserved_field_strip_would_leave() {
	for (name, value, expected) in [
		(
			"Authentication-Results",
			"mail.example.org; dkim=pass\r\n",
			"Authentication-Results",
		),
		("Received-SPF", "forged\r\n", "Received-SPF"),
		("Delivered-To", "alice@example.org\r\n", "Delivered-To"),
		("Return-Path", "<forged@example.org>\r\n", "Return-Path"),
		("Epistle-Class", "marketing\r\n", "Epistle-Class"),
		("X-Epistle", "forged\r\n", "X-Epistle"),
		("X-Spam-Status", "Yes\r\n", "X-Spam-Status"),
		("X-Spam-Score", "0.97\r\n", "X-Spam-Status"),
		(
			"X-Epistle-Attachment-Warning",
			"executable\r\n",
			"X-Epistle-Attachment-Warning",
		),
	] {
		let data = format!("{name}: {value}Subject: kept\r\n\r\nbody").into_bytes();
		assert_eq!(
			reserved_remaining(&data, HOST).unwrap_or(""),
			expected,
			"{name}"
		);
	}
}

/// The safety net must NOT flag a foreign, parseable `Authentication-Results`
/// (the stripper keeps it as untrusted information, by design) nor any
/// non-reserved field.
#[test]
fn safety_net_does_not_flag_foreign_or_unrelated_fields() {
	for data in [
		&b"Authentication-Results: other.example; spf=pass\r\nSubject: kept\r\n\r\nbody"[..],
		&b"From: eve@sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nbody"[..],
		&b"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=sender.example; s=external; h=from:to; bh=; b=\r\nSubject: kept\r\n\r\nbody"[..],
		&b"Authentication-Results: prior.example; spf=pass\r\nSubject: kept\r\n\r\nbody"[..],
		&b":Authentication-Results: prior.example; spf=pass\r\nSubject: kept\r\n\r\nbody"[..],
		&b"X-Epistlefoo: client\r\nSubject: kept\r\n\r\nbody"[..],
		&b":X-Epistlefoo: client\r\nSubject: kept\r\n\r\nbody"[..],
		&b"Subject: kept\r\n\r\n:X-Epistle: body"[..],
	] {
		assert!(reserved_remaining(data, HOST).is_none(), "{data:?}");
	}
}

/// The safety net compares names without regard to case: mail-parser keeps
/// the case of the names it does not know, so a lower-case spelling that
/// strip missed must still be refused.
#[test]
fn safety_net_ignores_the_case_of_the_name() {
	for (name, expected) in [
		("authentication-results", "Authentication-Results"),
		("AUTHENTICATION-RESULTS", "Authentication-Results"),
		("received-spf", "Received-SPF"),
		("delivered-to", "Delivered-To"),
		("return-path", "Return-Path"),
		("epistle-class", "Epistle-Class"),
		("x-epistle", "X-Epistle"),
		("x-spam-status", "X-Spam-Status"),
		("X-SPAM-Score", "X-Spam-Status"),
		(
			"x-epistle-attachment-warning",
			"X-Epistle-Attachment-Warning",
		),
	] {
		let data = format!("{name}: {HOST}; none\r\nSubject: kept\r\n\r\nbody").into_bytes();
		assert_eq!(
			reserved_remaining(&data, HOST).unwrap_or(""),
			expected,
			"{name}"
		);
	}
}

/// End-to-end through the strip-with-hole helper: a hole in the leader
/// fold lets `:Authentication-Results: x` survive strip; the safety net
/// must still flag it. This is what the SMTP path will hand the server
/// when run.rs calls `reserved_remaining` after `strip`.
#[test]
fn safety_net_catches_a_hypothetical_hole_in_strip() {
	for (name, expected) in [
		("Authentication-Results", "Authentication-Results"),
		("Received-SPF", "Received-SPF"),
		("Delivered-To", "Delivered-To"),
		("Return-Path", "Return-Path"),
		("Epistle-Class", "Epistle-Class"),
		("X-Epistle", "X-Epistle"),
		("X-Spam-Status", "X-Spam-Status"),
		("X-Spam-Score", "X-Spam-Status"),
		(
			"X-Epistle-Attachment-Warning",
			"X-Epistle-Attachment-Warning",
		),
	] {
		let mut data = format!(":{name}: forged\r\nSubject: kept\r\n\r\nbody").into_bytes();
		strip_buggy(&mut data, HOST);
		assert_eq!(
			reserved_remaining(&data, HOST).unwrap_or(""),
			expected,
			"{name}"
		);
		// And `strip` (with the leader fold) clears it, so the safety net
		// is the second pass, not the first.
		let mut fixed = format!(":{name}: forged\r\nSubject: kept\r\n\r\nbody").into_bytes();
		strip(&mut fixed, HOST);
		assert!(reserved_remaining(&fixed, HOST).is_none(), "{name}");
	}
}

/// Empty Authentication-Results values remain reserved. 1.0 represents
/// them as Text("") instead of Empty, so the authserv-id parser rejects
/// the empty text. Both representations must keep the same policy.
#[test]
fn reserved_remaining_flags_an_empty_authentication_results_value() {
	let original = b"Authentication-Results:\r\nSubject: kept\r\n\r\nbody";
	assert_eq!(
		reserved_remaining(original, HOST),
		Some("Authentication-Results"),
	);
}

#[test]
fn reserved_remaining_flags_an_empty_authentication_results_value_in_lowercase() {
	let original = b"authentication-results:\r\nSubject: kept\r\n\r\nbody";
	assert_eq!(
		reserved_remaining(original, HOST),
		Some("Authentication-Results"),
	);
}

/// Body amplification exposes repeated suffix shifts without move instrumentation.
#[test]
fn repeated_fields_compaction_cost_does_not_multiply_the_body() {
	fn elapsed(body_len: usize) -> std::time::Duration {
		let mut original = b"X-Spam-Status: forged\r\n".repeat(8_192);
		original.extend_from_slice(b"Subject: kept\r\n\r\n");
		original.resize(original.len() + body_len, 0xff);
		(0..3)
			.map(|_| {
				let mut data = original.clone();
				let start = std::time::Instant::now();
				strip(std::hint::black_box(&mut data), HOST);
				let elapsed = start.elapsed();
				assert_eq!(data.len(), b"Subject: kept\r\n\r\n".len() + body_len);
				std::hint::black_box(data);
				elapsed
			})
			.min()
			.unwrap()
	}
	let small = elapsed(64 * 1024);
	let large = elapsed(8 * 1024 * 1024);
	// Parsing is identical; one body copy permits a generous fixed margin.
	assert!(
		large < small * 12 + std::time::Duration::from_millis(50),
		"body amplification suggests repeated suffix moves: small={small:?}, large={large:?}"
	);
}
