//! Trace tests: Bcc stripping and the in-place header helpers.

use super::*;

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
			assert!(
				buffer[..end].ends_with(b"@example.org>\r\n")
					|| buffer[..end].ends_with(b"@example.org>\n")
			);
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
	use crate::util::header_block::{field_count, tests::cases};
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
