use super::*;

fn build_message(boundary: &str, parts: &[(String, String, String)]) -> Vec<u8> {
	// parts: (Content-Type header, Content-Transfer-Encoding, base64 body).
	let mut out = String::new();
	out.push_str("MIME-Version: 1.0\r\n");
	out.push_str(&format!(
		"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
	));
	out.push_str("\r\n");
	for (ct, cte, body) in parts {
		out.push_str(&format!("--{boundary}\r\n"));
		out.push_str(&format!("Content-Type: {ct}\r\n"));
		out.push_str(&format!("Content-Transfer-Encoding: {cte}\r\n"));
		out.push_str("\r\n");
		out.push_str(body);
		out.push_str("\r\n");
	}
	out.push_str(&format!("--{boundary}--\r\n"));
	out.into_bytes()
}

fn b64(bytes: &[u8]) -> String {
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn finds_the_gzip_attachment() {
	let payload = b"<feedback/>";
	let gz = {
		use flate2::write::GzEncoder;
		use std::io::Write;
		let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
		enc.write_all(payload).expect("write");
		enc.finish().expect("finish")
	};
	let message = build_message(
		"BOUND",
		&[
			("text/plain".into(), "7bit".into(), "intro".into()),
			("application/gzip".into(), "base64".into(), b64(&gz)),
		],
	);
	let found = find_report_part(&message, Kind::Dmarc).expect("found");
	assert_eq!(found.bytes, gz);
	assert_eq!(found.encoding, Encoding::Gzip);
}

#[test]
fn finds_the_zip_attachment_by_filename() {
	// Content-Type is `application/octet-stream`, the filename ends in
	// `.zip`. The walker must fall back to filename detection.
	fn build_zip(name: &str, payload: &[u8]) -> Vec<u8> {
		let mut out = Vec::new();
		out.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes()); // method = stored
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes()); // crc (unused by reader)
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&(name.len() as u16).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(name.as_bytes());
		out.extend_from_slice(payload);
		out
	}
	let zip = build_zip("report.xml", b"<feedback/>");
	let mut message = build_message(
		"BOUND",
		&[
			("text/plain".into(), "7bit".into(), "intro".into()),
			(
				"application/octet-stream".into(),
				"base64".into(),
				b64(&zip),
			),
		],
	);
	// Inject a Content-Disposition with the filename. The `build_message`
	// helper above does not emit it; rebuild manually for this test.
	let message_str = std::str::from_utf8(&message).expect("ascii").to_string();
	let replaced = message_str.replace(
		"Content-Type: application/octet-stream\r\n",
		"Content-Type: application/octet-stream\r\n\
		 Content-Disposition: attachment; filename=\"example.org.zip\"\r\n",
	);
	message = replaced.into_bytes();
	// The filename here is `example.org.zip`, not `report.xml`, because
	// the part's Content-Disposition overrides the in-zip name for our
	// filename detector.
	let found = find_report_part(&message, Kind::Dmarc).expect("found by filename");
	assert_eq!(found.encoding, Encoding::Zip);
	assert_eq!(found.bytes, zip);
}

#[test]
fn finds_the_tlsrpt_part() {
	let payload = b"{\"organization-name\":\"x\"}";
	let gz = {
		use flate2::write::GzEncoder;
		use std::io::Write;
		let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
		enc.write_all(payload).expect("write");
		enc.finish().expect("finish")
	};
	let message = build_message(
		"BOUND",
		&[("application/tlsrpt+gzip".into(), "base64".into(), b64(&gz))],
	);
	let found = find_report_part(&message, Kind::TlsRpt).expect("found");
	assert_eq!(found.bytes, gz);
	assert_eq!(found.encoding, Encoding::Gzip);
}

#[test]
fn a_message_without_a_report_part_is_none() {
	let message = build_message(
		"BOUND",
		&[
			("text/plain".into(), "7bit".into(), "hi".into()),
			("text/html".into(), "7bit".into(), "<p>hi</p>".into()),
		],
	);
	let err = find_report_part(&message, Kind::Dmarc).expect_err("no report part");
	assert!(matches!(err, WalkError::NoReportPart), "{err:?}");
}

/// A single-part message (no multipart at all) where the body itself is
/// the report. Google and Microsoft normally wrap in multipart, but a
/// minimal sender might not.
#[test]
fn finds_a_single_part_report() {
	let payload = b"<feedback/>";
	let gz = {
		use flate2::write::GzEncoder;
		use std::io::Write;
		let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
		enc.write_all(payload).expect("write");
		enc.finish().expect("finish")
	};
	let mut message = String::new();
	message.push_str("MIME-Version: 1.0\r\n");
	message.push_str("Content-Type: application/gzip\r\n");
	message.push_str("Content-Transfer-Encoding: base64\r\n");
	message.push_str("\r\n");
	message.push_str(&b64(&gz));
	let message = message.into_bytes();
	let found = find_report_part(&message, Kind::Dmarc).expect("single-part found");
	assert_eq!(found.bytes, gz);
}

/// A multipart inside a multipart inside a multipart exceeds the
/// nesting bound: the walker refuses and reports no report, rather
/// than walking the rest of the tree.
#[test]
fn nesting_past_the_bound_is_refused() {
	fn build(outer_boundary: &str, mid_boundary: &str, inner_boundary: &str) -> Vec<u8> {
		let mut out = String::new();
		out.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"{outer_boundary}\"\r\n\r\n"
		));
		out.push_str(&format!("--{outer_boundary}\r\n"));
		out.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"{mid_boundary}\"\r\n\r\n"
		));
		out.push_str(&format!("--{mid_boundary}\r\n"));
		out.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"{inner_boundary}\"\r\n\r\n"
		));
		out.push_str(&format!("--{inner_boundary}\r\n"));
		out.push_str("Content-Type: application/gzip\r\n");
		out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
		out.push_str(&b64(b"<feedback/>"));
		out.push_str("\r\n");
		out.push_str(&format!("--{inner_boundary}--\r\n"));
		out.push_str(&format!("--{mid_boundary}--\r\n"));
		out.push_str(&format!("--{outer_boundary}--\r\n"));
		out.into_bytes()
	}
	let message = build("A", "B", "C");
	let err = find_report_part(&message, Kind::Dmarc).expect_err("too deep");
	assert!(
		matches!(err, WalkError::NoReportPart),
		"too-deep nest stops at the bound and looks like no report, got {err:?}"
	);
}

/// A multipart body that never closes is hostile. Real senders include
/// the closing boundary; missing it means the buffer was truncated or
/// crafted. Either way we refuse.
#[test]
fn a_message_without_a_closing_boundary_is_refused() {
	let mut message = String::new();
	message.push_str("MIME-Version: 1.0\r\n");
	message.push_str("Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n");
	message.push_str("\r\n");
	message.push_str("--BOUND\r\n");
	message.push_str("Content-Type: application/gzip\r\n");
	message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
	message.push_str(&b64(b"<feedback/>"));
	message.push_str("\r\n");
	// No closing boundary "--BOUND--".
	let message = message.into_bytes();
	let err = find_report_part(&message, Kind::Dmarc).expect_err("missing closing");
	assert!(
		matches!(err, WalkError::Malformed("missing closing boundary")),
		"{err:?}"
	);
}

/// A base64 part whose decoded upper bound already exceeds
/// [`MAX_COMPRESSED`] is refused before the decoder allocates the
/// result.
#[test]
fn base64_larger_than_max_compressed_is_refused() {
	// 4 base64 characters decode to at most 3 bytes. To exceed
	// MAX_COMPRESSED (2 MiB) we need at least ceil(2 MiB * 4 / 3)
	// base64 characters.
	let bytes_per_4 = 3usize;
	let needed_chars = MAX_COMPRESSED * 4 / bytes_per_4 + 16;
	let payload = vec![b'A'; needed_chars];
	let mut message = String::new();
	message.push_str("MIME-Version: 1.0\r\n");
	message.push_str("Content-Type: application/gzip\r\n");
	message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
	message.push_str(&b64(&payload));
	let message = message.into_bytes();
	let err = find_report_part(&message, Kind::Dmarc).expect_err("base64 bomb");
	assert!(matches!(err, WalkError::TooLarge), "{err:?}");
}

/// 64 parts fit; 65 parts are refused with the matching error.
#[test]
fn a_message_with_too_many_parts_is_refused() {
	let mut message = String::new();
	message.push_str("MIME-Version: 1.0\r\n");
	message.push_str("Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n");
	for i in 0..65 {
		message.push_str("--BOUND\r\n");
		message.push_str(&format!("Content-Type: text/plain\r\n\r\npart {i}\r\n"));
	}
	message.push_str("--BOUND--\r\n");
	let message = message.into_bytes();
	let err = find_report_part(&message, Kind::Dmarc).expect_err("too many parts");
	assert!(
		matches!(err, WalkError::Malformed("too many parts")),
		"{err:?}"
	);
}

/// Craft the input the issue names: a boundary of 64 KiB of hyphens plus a
/// trailing byte, declared in a multipart Content-Type, with a body of
/// hyphens the search would otherwise have to walk. The boundary is
/// invalid per RFC 2046 (70-octet cap) and the walker must refuse
/// it before the linear scan runs. The work counter must stay
/// proportional to the body length, not the body times the boundary
/// length, which is the shape the sabotage reintroduces.
#[test]
fn boundary_over_70_octets_is_refused_with_bounded_work() {
	let boundary: String = "-".repeat(65_536);
	let body_len: usize = 1 << 20; // 1 MiB of hyphens
	let mut raw = Vec::with_capacity(body_len + 128);
	raw.extend_from_slice(
		format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n").as_bytes(),
	);
	raw.extend(std::iter::repeat_n(b'-', body_len));
	reset_scan_steps();
	let err = find_report_part(&raw, Kind::Dmarc).expect_err("oversized boundary refused");
	let steps = reset_scan_steps();
	assert!(
		matches!(err, WalkError::Malformed("boundary too long")),
		"expected boundary-too-long error, got {err:?}"
	);
	// The cap check is O(1); the search never runs. The dominant cost
	// in the counter is the header scan (`find_headers_end` calls
	// `find_subslice` to locate `\r\n\r\n` and `\n\n`), which is
	// O(body.len()). A 70-octet cap is enough to keep the total work
	// proportional to the body length. The sabotage (no cap) runs
	// `find_subslice` with a 64 KiB needle on every position and
	// drives the counter past body.len() * 64 KiB.
	assert!(
		steps <= body_len as u64 * 200,
		"oversized boundary forced search work: {steps} steps for {body_len} bytes"
	);
}

fn gzip_b64_of(payload: &[u8]) -> Vec<u8> {
	use flate2::write::GzEncoder;
	use std::io::Write;
	let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
	enc.write_all(payload).expect("write");
	let gz = enc.finish().expect("finish");
	b64(&gz).into_bytes()
}

/// Two parts: the first is a text/plain body of `body_len` characters
/// that cannot match a `--<boundary>` prefix, the second is the gzip
/// DMARC report at the tail of the multipart. The first part is
/// non-matching so the walker has to walk the entire body to reach
/// the report at the end. The earlier fixture used a body of hyphens
/// which matched the boundary at its very start, so a quadratic
/// `find_subslice` could exit at the first occurrence and the test
/// never proved the closing boundary was reached; using `x` removes
/// that escape route.
fn build_multipart_with_clean_body(boundary: &str, body_len: usize) -> Vec<u8> {
	let mut raw = Vec::new();
	raw.extend_from_slice(
		format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n").as_bytes(),
	);
	raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
	raw.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
	raw.extend(std::iter::repeat_n(b'x', body_len));
	raw.extend_from_slice(b"\r\n");
	raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
	raw.extend_from_slice(b"Content-Type: application/gzip\r\n");
	raw.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n\r\n");
	raw.extend(gzip_b64_of(b"<feedback/>"));
	raw.extend_from_slice(b"\r\n");
	raw.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
	raw
}

/// A boundary at the 70-octet cap and a body of `x` characters
/// (non-matching) followed by the gzip report at the tail: the linear
/// scan must walk the body once and only check each line's prefix
/// against the boundary. Doubling the body must at most roughly double
/// the step counter, with a fixed slack for the per-call overhead.
/// The test additionally asserts the decoded report's bytes and
/// encoding, which proves the parser walked all the way to the last
/// part instead of stopping at a false early match in the body.
#[test]
fn doubling_the_crafted_input_at_most_doubles_the_step_count() {
	let boundary: String = "-".repeat(MAX_BOUNDARY_LEN);
	let small_body = 1 << 19;
	let large_body = 1 << 20;
	let small = build_multipart_with_clean_body(&boundary, small_body);
	let large = build_multipart_with_clean_body(&boundary, large_body);
	reset_scan_steps();
	let small_found = find_report_part(&small, Kind::Dmarc).expect("small parses");
	let small_steps = reset_scan_steps();
	reset_scan_steps();
	let large_found = find_report_part(&large, Kind::Dmarc).expect("large parses");
	let large_steps = reset_scan_steps();
	// linear: count(2N) <= 2 * count(N) + slack
	assert!(
		large_steps as u128 <= small_steps as u128 * 2 + 4096,
		"step count grew superlinearly: small={small_steps}, large={large_steps}"
	);
	// Absolute bound. The historical per-position `find_subslice` was
	// O(body * needle): for a 1 MiB body and the 72-octet boundary
	// prefix it would charge ~72 million comparisons, well above the
	// few-million linear-scan cost. The two-piece fixture means there
	// is no early false match in the body to escape through, so the
	// linear scan must walk the long `x` line and the per-line work
	// is bounded.
	assert!(
		large_steps < 10_000_000,
		"step count blew past the linear scan bound: {large_steps} for {large_body} bytes"
	);
	let expected_gz = {
		use flate2::write::GzEncoder;
		use std::io::Write;
		let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
		enc.write_all(b"<feedback/>").expect("write");
		enc.finish().expect("finish")
	};
	assert_eq!(
		small_found.bytes, expected_gz,
		"closing-delimiter reached decodes the full report (small)"
	);
	assert_eq!(
		large_found.bytes, expected_gz,
		"closing-delimiter reached decodes the full report (large)"
	);
	assert_eq!(small_found.encoding, Encoding::Gzip);
	assert_eq!(large_found.encoding, Encoding::Gzip);
}

/// Build a multipart whose body between the opening and closing
/// boundaries is a near-match for the 70-hyphen boundary: 71 hyphens
/// followed by 'x', repeated. The needle is 72 hyphens (`--` + 70
/// hyphens). Every 72-byte window holds a mismatch at byte 71 (or
/// earlier, when the window is shifted by 1), so no position in the
/// body contains a full 72-byte match for the needle. The closing
/// boundary sits at the very end of the body, so the search has to
/// walk the whole near-match to find it.
fn build_multipart_with_near_match_body(boundary: &str, body_len: usize) -> Vec<u8> {
	let mut raw = Vec::new();
	raw.extend_from_slice(
		format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n").as_bytes(),
	);
	raw.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
	raw.extend_from_slice(b"Content-Type: application/gzip\r\n");
	raw.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n\r\n");
	let gz = {
		use flate2::write::GzEncoder;
		use std::io::Write;
		let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
		enc.write_all(b"<feedback/>").expect("write");
		enc.finish().expect("finish")
	};
	raw.extend_from_slice(b64(&gz).as_bytes());
	raw.extend_from_slice(b"\r\n");
	// 71 hyphens + 'x' = 72 bytes. Every 72-byte window in the repeated
	// body has a mismatch at byte 71 (the 'x'), so the 72-byte needle
	// has no full match anywhere in the body. The closing boundary
	// only matches because its first 72 bytes are exactly the needle.
	let pattern = format!("{}x", "-".repeat(MAX_BOUNDARY_LEN + 1));
	let repeats = body_len / pattern.len();
	let body = pattern.repeat(repeats);
	raw.extend_from_slice(body.as_bytes());
	raw.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
	raw
}

/// The near-match fixture exposes the difference between the linear
/// scan and the historical `find_subslice` search. The needle is 72
/// hyphens (`--` + 70 hyphens) and the body is the periodic
/// 71-hyphen + 'x' pattern, so the body has no full match anywhere.
/// The historical `find_subslice` would walk every position, comparing
/// 72 bytes at each step, which for a 1 MiB body is on the order of
/// 72 million compares. The linear scan checks one line's prefix and
/// stops after the single mismatch. The bound sits well above the
/// linear scan and well below `find_subslice`.
#[test]
fn delimiter_scan_stays_bounded_on_a_near_match_ending_in_a_different_byte() {
	let boundary: String = "-".repeat(MAX_BOUNDARY_LEN);
	let body_len: usize = 1 << 20; // 1 MiB
	let raw = build_multipart_with_near_match_body(&boundary, body_len);
	reset_scan_steps();
	let _ = find_report_part(&raw, Kind::Dmarc);
	let steps = reset_scan_steps();
	// The find_subslice algorithm would record O(body_len * 72)
	// compares for the boundary search, which is around 75 million
	// for a 1 MiB body. The header scan in `find_headers_end`
	// contributes another O(body_len) for the `\n\n` fallback, which
	// the linear and historical search share. The bound sits well
	// above the linear scan (a few million) and well below the
	// quadratic path (`O(body * needle)`).
	let bound: u64 = 10_000_000;
	assert!(
		steps <= bound,
		"delimiter scan did O(body * needle) work: {steps} steps for {body_len} bytes"
	);
}
