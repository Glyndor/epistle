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
