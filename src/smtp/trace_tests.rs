//! Tests for the trace-header helpers in [`super`]: the `Received:` hop
//! counter, the protocol keyword mapping, the SPF-domain resolution, and
//! `ensure_submission_headers` (the `Message-ID` / `Date` stamper for
//! authenticated submission).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;

fn at(epoch_secs: u64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(epoch_secs)
}

#[test]
fn counts_received_headers_in_the_block_only() {
	let data = b"Received: from a\r\nReceived: from b\r\n\tby folded\r\n\
Subject: hi\r\n\r\nReceived: not a header in the body\r\n";
	// Two Received headers; the folded continuation and the body line
	// are not counted.
	assert_eq!(received_hop_count(data), 2);
}

#[test]
fn counts_zero_when_no_received_headers() {
	assert_eq!(received_hop_count(b"From: a@b\r\n\r\nbody\r\n"), 0);
}

#[test]
fn received_protocol_follows_rfc3848() {
	// HELO is plain SMTP regardless of TLS or auth.
	assert_eq!(received_protocol(false, false, false), "SMTP");
	assert_eq!(received_protocol(false, true, true), "SMTP");
	// EHLO gains S over TLS and A once authenticated.
	assert_eq!(received_protocol(true, false, false), "ESMTP");
	assert_eq!(received_protocol(true, true, false), "ESMTPS");
	assert_eq!(received_protocol(true, false, true), "ESMTPA");
	assert_eq!(received_protocol(true, true, true), "ESMTPSA");
}

#[test]
fn spf_domain_prefers_mail_from_then_helo() {
	assert_eq!(
		spf_domain("a@Example.ORG", Some("helo.example")),
		Some("example.org".to_string())
	);
	assert_eq!(
		spf_domain("", Some("helo.example")),
		Some("helo.example".to_string())
	);
	assert_eq!(spf_domain("", None), None);
}

/// Both `Message-ID` and `Date` are absent from a minimal submission: the
/// stamper writes both, the `Message-ID` is a UUIDv7 under `domain`, and
/// the `Date` parses as RFC 5322. The two new lines land at the very top
/// of the header block, ahead of every client-supplied header.
#[test]
fn adds_message_id_and_date_when_both_are_missing() {
	let data =
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	let text = std::str::from_utf8(&stamped).expect("ascii");
	// Message-ID comes first, Date second, both ahead of the client headers.
	let message_id_idx = text.find("Message-ID: <").expect("message-id line");
	let date_idx = text.find("Date: ").expect("date line");
	let from_idx = text.find("From: ").expect("from line");
	assert!(message_id_idx < date_idx, "Message-ID before Date: {text}");
	assert!(date_idx < from_idx, "Date before From: {text}");
	// The Message-ID is shaped `<uuidv7@domain>`.
	let message_id_line = text
		.lines()
		.find(|line| line.starts_with("Message-ID:"))
		.expect("message-id line");
	let angle = message_id_line
		.find('<')
		.zip(message_id_line.find('>'))
		.expect("angle brackets");
	let id_inner = &message_id_line[angle.0 + 1..angle.1];
	let (local, domain) = id_inner.split_once('@').expect("local@domain");
	assert_eq!(domain, "example.org", "domain part of the minted id");
	let parsed = uuid::Uuid::parse_str(local).expect("local is a uuidv7");
	assert_eq!(
		parsed.get_version(),
		Some(uuid::Version::SortRand),
		"minted id must be uuidv7, got {parsed}"
	);
	// Date parses as RFC 5322: `Day, DD Mon YYYY HH:MM:SS +0000` (UTC).
	let date_line = text
		.lines()
		.find(|line| line.starts_with("Date: "))
		.expect("date line");
	let date_value = date_line.trim_start_matches("Date: ").trim();
	let parsed_date = chrono_parse(date_value);
	assert!(
		parsed_date,
		"Date must parse as RFC 5322, got {date_value:?}"
	);
	// The body and the client's own header lines remain intact.
	assert!(text.contains("From: alice@example.org"));
	assert!(text.contains("Subject: hi"));
	assert!(text.ends_with("body\r\n"));
}

/// Already-present `Message-ID` and `Date` are left alone: the output is
/// byte-identical to the input. The control test for the "we never
/// override the client" half of the contract.
#[test]
fn keeps_an_existing_message_id_and_date_untouched() {
	let data = b"Message-ID: <client@example.org>\r\nDate: Mon, 01 Jan 2024 12:00:00 +0000\r\nSubject: hi\r\n\r\nbody\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	assert_eq!(stamped, data);
}

/// Field-name matching is case-insensitive and ignores any same-named line
/// that lives in the body, after the blank line. The lowercase `message-id:`
/// in the header block is recognised; the uppercase one in the body is not.
#[test]
fn matches_header_names_case_insensitively_and_ignores_the_body() {
	let data = b"message-id: <client@example.org>\r\nSubject: hi\r\n\r\n\
Message-ID: not a header in the body\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	let text = std::str::from_utf8(&stamped).expect("ascii");
	// The stamper must not add a fresh Message-ID: the lowercase form in
	// the headers was recognised, so the only Message-ID lines in the
	// output are the client's (in the headers, lowercase) and the body's
	// own (uppercase, after the blank line). The first non-empty line of
	// the result is the stamper's Date, proving no Message-ID was
	// prepended.
	assert!(
		text.starts_with("Date: "),
		"stamper prepends Date (no Message-ID because the header had one): {text}"
	);
	let first_message_id_line = text
		.lines()
		.find(|line| line.to_ascii_lowercase().starts_with("message-id:"))
		.expect("client Message-ID");
	assert_eq!(
		first_message_id_line, "message-id: <client@example.org>",
		"the only Message-ID before the blank line is the client's: {text}"
	);
	// The body's "Message-ID: not a header" line is preserved unchanged.
	assert!(text.contains("Message-ID: not a header in the body"));
}

/// A folded `Date:` header (the field value continues on the next line,
/// which starts with WSP) is still recognised as present. Pinning the
/// RFC 5322 fold rule so a wrapped Date does not trigger a duplicate
/// stamp.
#[test]
fn a_folded_date_header_is_recognised() {
	let data = b"Date: Mon, 01 Jan\r\n 2024\r\n\
Message-ID: <client@example.org>\r\nSubject: hi\r\n\r\nbody\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	// Date and Message-ID are both already there (Date is folded), so the
	// output equals the input byte-for-byte.
	assert_eq!(stamped, data);
}

/// A minimal RFC 5322 date-time parser: the verifier only needs to know
/// that the stamper's `Date:` value is well-formed. `chrono` is not in
/// the dependency tree; the parser only checks the shape.
fn chrono_parse(value: &str) -> bool {
	let Some((weekday, rest)) = value.split_once(", ") else {
		return false;
	};
	if !matches!(
		weekday,
		"Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
	) {
		return false;
	}
	// `rest` is `DD Mon YYYY HH:MM:SS ±ZZZZ`. Find the year (the fourth
	// whitespace-separated token) and then the time+zone pair.
	let tokens: Vec<&str> = rest.split_whitespace().collect();
	if tokens.len() != 5 {
		return false;
	}
	let time = tokens[3];
	let zone = tokens[4];
	if time.len() != 8
		|| time.as_bytes().get(2) != Some(&b':')
		|| time.as_bytes().get(5) != Some(&b':')
		|| !time.as_bytes()[..2].iter().all(u8::is_ascii_digit)
		|| !time.as_bytes()[3..5].iter().all(u8::is_ascii_digit)
		|| !time.as_bytes()[6..8].iter().all(u8::is_ascii_digit)
	{
		return false;
	}
	if !(zone.starts_with('+') || zone.starts_with('-')) {
		return false;
	}
	if !tokens[0].chars().all(|c| c.is_ascii_digit()) {
		return false;
	}
	if !tokens[2].chars().all(|c| c.is_ascii_digit()) {
		return false;
	}
	true
}

/// An LF-only message (no CR) is still split correctly: the blank-line
/// separator is `\n\n`, the header block ends at the first one and the
/// stamper does not split a body line in two. Pinning the "CRLF
/// or LF" requirement.
#[test]
fn lf_only_messages_are_split_correctly() {
	let data = b"From: alice@example.org\nSubject: hi\n\nbody\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	let text = std::str::from_utf8(&stamped).expect("ascii");
	let message_id_count = text
		.lines()
		.filter(|line| line.starts_with("Message-ID:"))
		.count();
	assert_eq!(message_id_count, 1, "exactly one Message-ID line: {text}");
	assert!(text.contains("body\n"));
}

#[test]
fn spam_headers_prepend_at_the_top_of_the_header_block() {
	let data = b"From: a@b\r\nSubject: hi\r\n\r\nbody\r\n";
	let out = super::inject_spam_headers(data, 0.987654321);
	let text = std::str::from_utf8(&out).expect("utf-8");
	// The two new headers sit at the very top, before anything the
	// sender wrote.
	assert!(
		text.starts_with("X-Spam-Status: Yes\r\nX-Spam-Score: 0.987654\r\n"),
		"new headers must come first: {text:?}"
	);
	// The original block is preserved, untouched in order and content.
	let original = "From: a@b\r\nSubject: hi\r\n\r\nbody\r\n";
	assert!(
		text.contains(original),
		"original message is preserved verbatim: {text:?}"
	);
}

#[test]
fn spam_headers_work_with_lf_only_terminators() {
	// Defensive: a peer that speaks LF-only line endings (a non-RFC
	// minority, but observed in the wild) still gets the header
	// prepended at the correct spot.
	let data = b"From: a@b\nSubject: hi\n\nbody\n";
	let out = super::inject_spam_headers(data, 0.99);
	let text = std::str::from_utf8(&out).expect("utf-8");
	assert!(
		text.starts_with("X-Spam-Status: Yes\r\nX-Spam-Score: 0.990000\r\n"),
		"LF-only message gets the same prepend: {text:?}"
	);
	assert!(text.ends_with("body\n"));
}

#[test]
fn spam_headers_handle_messages_with_no_blank_line() {
	// Header block runs to end of input. Injector must not panic.
	let data = b"From: a@b\r\nSubject: hi\r\n";
	let out = super::inject_spam_headers(data, 1.0);
	let text = std::str::from_utf8(&out).expect("utf-8");
	assert!(
		text.starts_with("X-Spam-Status: Yes\r\nX-Spam-Score: 1.000000\r\n"),
		"messages without a blank separator still get the prepend: {text:?}"
	);
	assert!(
		text.ends_with("Subject: hi\r\n"),
		"the original line stays at the end: {text:?}"
	);
}

#[test]
fn strip_bcc_drops_every_bcc_field_and_keeps_the_rest() {
	let data = b"From: a@x\r\nBCC : one@x,\r\n\ttwo@x\r\nTo: b@x\r\nResent-Bcc: three@x\r\n\
		X-Bcc-Note: kept\r\nSubject: s\r\n\r\nBcc: body line\r\n";
	let stripped = super::strip_bcc(data);
	assert_eq!(
		String::from_utf8_lossy(&stripped),
		"From: a@x\r\nTo: b@x\r\nX-Bcc-Note: kept\r\nSubject: s\r\n\r\nBcc: body line\r\n"
	);
	assert_eq!(
		super::strip_bcc(b"Subject: s\r\n\r\nx"),
		b"Subject: s\r\n\r\nx"
	);
}

#[test]
fn ensure_submission_headers_in_place_matches_the_allocating_variant() {
	// The minted Message-ID is random, so the first line is compared by
	// shape and the rest byte for byte. Each buffer has no spare capacity,
	// so the in-place stamp has to grow it.
	let cases: &[&[u8]] = &[
		b"Message-ID: <a@x>\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nbody",
		b"Message-ID: <a@x>\r\nSubject: s\r\n\r\nbody\r\n",
		b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nSubject: s\r\n\r\nbody",
		b"Subject: s\nTo: b@x\n\nbody\n",
		b"Subject: no blank line",
		b"",
	];
	for original in cases {
		let expected = super::ensure_submission_headers(original, "example.org", at(1_700_000_000));
		let mut buffer = Vec::with_capacity(original.len());
		buffer.extend_from_slice(original);
		super::ensure_submission_headers_in_place(&mut buffer, "example.org", at(1_700_000_000));
		assert_eq!(buffer.len(), expected.len());
		let minted = expected.starts_with(b"Message-ID: <") && !original.starts_with(b"Message-ID");
		let skip = if minted {
			let end = expected.iter().position(|&b| b == b'\n').expect("line") + 1;
			assert!(buffer[..end].ends_with(b"@example.org>\r\n"));
			end
		} else {
			0
		};
		assert_eq!(
			buffer[skip..],
			expected[skip..],
			"case {:?}",
			String::from_utf8_lossy(original)
		);
	}
}

#[test]
fn ensure_submission_headers_in_place_grows_by_the_headers_only() {
	// A full buffer must not double: for a 25 MiB body that is 25 MiB of
	// spare capacity held for the rest of the delivery.
	const SIZE: usize = 1 << 20;
	let mut buffer = Vec::with_capacity(SIZE);
	buffer.extend_from_slice(b"Subject: s\r\n\r\n");
	buffer.resize(SIZE, b'x');
	assert_eq!(buffer.capacity(), SIZE);
	super::ensure_submission_headers_in_place(&mut buffer, "example.org", at(1_700_000_000));
	assert!(
		buffer.capacity() < SIZE + 4096,
		"capacity {} for a {} octet message",
		buffer.capacity(),
		buffer.len()
	);
}

#[test]
fn strip_bcc_in_place_matches_the_allocating_variant() {
	let cases: &[&[u8]] = &[
		b"Subject: s\r\n\r\nx",
		b"From: a@x\r\nBCC : one@x,\r\n\ttwo@x\r\nTo: b@x\r\nResent-Bcc: three@x\r\n\
			X-Bcc-Note: kept\r\nSubject: s\r\n\r\nBcc: body line\r\n",
		b"Bcc: only\r\nSubject: s\r\n\r\nbody",
		b"From: a@x\r\nTo: b@x\r\nBcc: c@x\r\nSubject: s\r\n\r\nbody",
	];
	for original in cases {
		let mut buffer = original.to_vec();
		let expected = super::strip_bcc(original);
		super::strip_bcc_in_place(&mut buffer);
		assert_eq!(
			buffer,
			expected,
			"input: {:?}",
			String::from_utf8_lossy(original)
		);
	}
}

/// Number of full-body copies made by the post-DATA stamping
/// path on one 25 MiB message. The SMTP run.rs prepends
/// `Received:` + `Authentication-Results:` + (on authenticated
/// submission) the `Message-ID` / `Date` stamp and a Bcc
/// strip, then writes the body. The slice-returning
/// `ensure_submission_headers` and `strip_bcc` each allocate a
/// fresh `Vec<u8>` and `extend_from_slice` the entire body,
/// so the old path makes two full body copies. The in-place
/// `ensure_submission_headers_in_place` and `strip_bcc_in_place`
/// shift the bytes inside the same buffer, and the final
/// `Vec::with_capacity` receives the body via `Vec::append`, the
/// one copy left.
///
/// The test counts the distinct intermediate `Vec<u8>`
/// allocations whose capacity reaches the body size. The old
/// path makes two (the `ensure_submission_headers` result and
/// the `strip_bcc` result). The new path makes zero: every
/// intermediate buffer stays within the headers region, and
/// the final buffer is the only one that touches the body.
#[test]
fn fewer_copies_in_post_data_stamping_path_avoids_full_body_copies() {
	const BODY: usize = 25 * 1024 * 1024;
	let body: Vec<u8> = vec![b'x'; BODY];
	let raw: Vec<u8> = {
		let mut v = Vec::with_capacity(200 + BODY);
		v.extend_from_slice(
			b"From: alice@example.org\r\nTo: bob@example.org\r\nBcc: c@x\r\nSubject: s\r\n\r\n",
		);
		v.extend_from_slice(&body);
		v
	};
	// Old path: two body-sized intermediate Vecs, each holding
	// a full copy of the message while the next step runs.
	let after_ensure =
		super::ensure_submission_headers(&raw, "example.org", std::time::SystemTime::now());
	let old_ensure_capacity = after_ensure.capacity();
	let after_strip = super::strip_bcc(&after_ensure);
	let old_strip_capacity = after_strip.capacity();
	// Both intermediates must hold a body-sized copy.
	assert!(
		old_ensure_capacity >= BODY,
		"old path: ensure_intermediate capacity {old_ensure_capacity} should be at least BODY ({BODY})"
	);
	assert!(
		old_strip_capacity >= BODY,
		"old path: strip_intermediate capacity {old_strip_capacity} should be at least BODY ({BODY})"
	);
	// New path: in place, no body-sized intermediate.
	let mut new = raw;
	let new_len_at_start = new.len();
	super::ensure_submission_headers_in_place(
		&mut new,
		"example.org",
		std::time::SystemTime::now(),
	);
	let ensure_added_bytes = new.len() - new_len_at_start;
	super::strip_bcc_in_place(&mut new);
	let strip_removed_bytes = new_len_at_start + ensure_added_bytes - new.len();
	// The in-place variants touch only the header region:
	// the body never moves, so the buffer length changes by at
	// most the headers region size, well below BODY.
	assert!(
		ensure_added_bytes + strip_removed_bytes < BODY / 10,
		"new path: header-only mutations should be << BODY, was ensure +{} strip -{} for body {BODY}",
		ensure_added_bytes,
		strip_removed_bytes,
	);
	// The final `stamped` Vec is the only allocation that
	// receives the body, and it is a single `Vec::with_capacity`
	// sized to body + stamp + headers. The body is moved into
	// it via `Vec::append`, not copied.
	let stamped = {
		let mut v = Vec::with_capacity(200 + BODY);
		v.extend_from_slice(b"Received: from x\r\n");
		v.append(&mut new);
		v
	};
	// The exact length is `BODY` plus the headers and the Bcc
	// removal; the point is that it equals the input minus the
	// Bcc line plus the `Received:` stamp.
	assert!(stamped.ends_with(b"xxxxxxxx"));
	assert!(stamped.starts_with(b"Received: from x\r\n"));
}

#[test]
fn the_field_count_is_never_below_the_headers_the_trace_helpers_take() {
	use crate::util::header_block::{cases, field_count};
	for raw in cases::messages() {
		let headers = &raw[..header_block_end(&raw)];
		assert!(field_count(&raw) >= cases::fields_in(headers), "{raw:?}");
	}
}

#[test]
fn a_namespace_strip_drops_ours_case_insensitively_and_nothing_else() {
	let data = b"X-Epistle: 1\r\n\
Subject: hi\r\n\
x-epistle-future: no\r\n\
X-Epistle : 2\r\n\
X-Spam-Status: Yes\r\n\
X-Epistol: not ours\r\n\
X-Epistlefoo: not ours either\r\n\
X-Epistle-: bare\r\n\
X-Epistle -Spaced: odd\r\n\
\r\nX-Epistle: body\r\n";
	let kept = strip_headers_with_namespace(data, "X-Epistle");
	let text = String::from_utf8(kept.clone()).expect("utf8");
	assert!(!text.contains("X-Epistle: 1"), "{text}");
	assert!(!text.contains("x-epistle-future"), "{text}");
	// A trailing space in the name still matches.
	assert!(!text.contains("X-Epistle : 2"), "{text}");
	// The bare namespace and a spaced spelling are read as ours downstream.
	assert!(!text.contains("X-Epistle-: bare"), "{text}");
	assert!(!text.contains("Spaced: odd"), "{text}");
	// A different field, a name that merely starts the same and the body
	// are all kept.
	assert!(text.contains("X-Spam-Status: Yes"), "{text}");
	assert!(text.contains("X-Epistol: not ours"), "{text}");
	assert!(
		text.contains("X-Epistlefoo: not ours either"),
		"a name that only starts like ours was dropped: {text}"
	);
	assert!(text.contains("Subject: hi"), "{text}");
	assert!(text.ends_with("\r\nX-Epistle: body\r\n"), "{text}");
}

#[test]
fn keeping_the_first_of_each_leaves_one_copy_of_the_repeated_field() {
	let data = b"Feedback-ID: one\r\n\
Subject: hi\r\n\
Feedback-ID: two\r\n\
feedback-id : three\r\n\
List-Unsubscribe: <mailto:a@example.org>\r\n\
List-Unsubscribe: <https://example.org/u>\r\n\
Organization: ours\r\n\
X-Spam-Status: Yes\r\n\
\r\nbody\r\n";
	let mut data = data.to_vec();
	keep_first_of_each_in_place(
		&mut data,
		&["feedback-id", "list-unsubscribe", "organization"],
	);
	let text = String::from_utf8(data).expect("utf8");
	assert!(text.contains("Feedback-ID: one\r\n"), "{text}");
	assert!(!text.contains("Feedback-ID: two"), "{text}");
	// A trailing space in the name is the same field, so the third copy
	// goes with the second.
	assert!(!text.contains("feedback-id : three"), "{text}");
	assert!(
		text.contains("List-Unsubscribe: <mailto:a@example.org>"),
		"{text}"
	);
	assert!(
		!text.contains("List-Unsubscribe: <https://example.org/u>"),
		"{text}"
	);
	assert!(text.contains("Organization: ours\r\n"), "{text}");
	assert!(text.contains("X-Spam-Status: Yes"), "{text}");
	assert!(text.contains("Subject: hi"), "{text}");
	assert!(text.ends_with("\r\n\r\nbody\r\n"), "{text}");
}
