use super::*;
use crate::antispam::attachments::corpus;

const LIMITS: Limits = Limits {
	max_depth: 10,
	max_parts: 1000,
	max_decoded: 1 << 20,
	deadline: None,
};

fn leaves(raw: &[u8], limits: &Limits) -> (Vec<Leaf>, Result<usize, Stop>) {
	let mut out = Vec::new();
	let walked = walk(raw, limits, |leaf| out.push(leaf));
	let result = match walked.stopped {
		Some(stop) => Err(stop),
		None => Ok(walked.parts),
	};
	(out, result)
}

#[test]
fn an_attachment_comes_with_its_name_declared_type_and_decoded_content() {
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: image/jpeg; name=\"ignored.jpg\"\r\n\
		 Content-Disposition: attachment; filename=\"photo.jpg\"",
		&corpus::pe(),
	)]);
	let (found, result) = leaves(&raw, &LIMITS);
	assert_eq!(result, Ok(3), "the container, the text and the attachment");
	assert_eq!(found.len(), 2);
	assert!(!found[0].attachment, "the text body is not an attachment");
	assert_eq!(found[0].declared_type, "text/plain");
	let attachment = &found[1];
	assert!(attachment.attachment);
	assert_eq!(attachment.filename(), Some("photo.jpg"));
	assert_eq!(attachment.declared_type, "image/jpeg");
	assert_eq!(attachment.depth, 1);
	assert!(
		attachment.content == corpus::pe(),
		"decoded content differs"
	);
	assert!(!attachment.truncated);
}

#[test]
fn the_content_type_name_is_used_when_the_disposition_has_none() {
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: application/octet-stream; name=\"setup.exe\"",
		b"data",
	)]);
	let (found, _) = leaves(&raw, &LIMITS);
	assert_eq!(found.len(), 2, "the text and the attachment");
	assert_eq!(found[1].filename(), Some("setup.exe"));
}

#[test]
fn an_rfc2231_continued_and_encoded_filename_is_decoded() {
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: application/octet-stream\r\n\
		 Content-Disposition: attachment;\r\n filename*0*=utf-8''r%C3%A9sum%C3%A9;\r\n filename*1=\".pdf.exe\"",
		b"data",
	)]);
	let (found, _) = leaves(&raw, &LIMITS);
	assert_eq!(found.len(), 2, "the text and the attachment");
	assert_eq!(found[1].filename(), Some("résumé.pdf.exe"));
}

#[test]
fn quoted_printable_and_identity_bodies_are_decoded() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: application/octet-stream; name=a.bin\r\n\
		Content-Transfer-Encoding: quoted-printable\r\n\r\nMZ=00=01\r\n--b\r\n\
		Content-Type: application/octet-stream; name=b.bin\r\n\r\nraw\r\n--b--\r\n";
	let (found, result) = leaves(raw, &LIMITS);
	assert_eq!(result, Ok(3));
	assert_eq!(found[0].content, b"MZ\x00\x01");
	assert_eq!(found[1].content, b"raw");
}

fn nested(levels: usize) -> Vec<u8> {
	let mut out = String::new();
	for level in 0..levels {
		out.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
		));
	}
	out.push_str("Content-Type: application/octet-stream; name=deep.exe\r\n\r\nMZ\r\n");
	for level in (0..levels).rev() {
		out.push_str(&format!("--b{level}--\r\n"));
	}
	out.into_bytes()
}

#[test]
fn nesting_up_to_ten_levels_is_walked_and_the_eleventh_stops_the_walk() {
	let (found, result) = leaves(&nested(10), &LIMITS);
	assert_eq!(result, Ok(11));
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].depth, 10);
	assert_eq!(found[0].filename(), Some("deep.exe"));
	let (_, result) = leaves(&nested(11), &LIMITS);
	assert_eq!(result, Err(Stop::TooDeep));
}

fn many_parts(count: usize) -> Vec<u8> {
	let mut out = String::from("Content-Type: multipart/mixed; boundary=p\r\n\r\n");
	for index in 0..count {
		out.push_str(&format!(
			"--p\r\nContent-Type: application/octet-stream; name={index}.bin\r\n\r\nx\r\n"
		));
	}
	out.push_str("--p--\r\n");
	out.into_bytes()
}

#[test]
fn a_thousand_parts_are_walked_and_one_more_stops_the_walk() {
	let (found, result) = leaves(&many_parts(999), &LIMITS);
	assert_eq!(result, Ok(1000));
	assert_eq!(found.len(), 999);
	let (found, result) = leaves(&many_parts(1000), &LIMITS);
	assert_eq!(result, Err(Stop::TooManyParts));
	assert_eq!(
		found.len(),
		999,
		"leaves before the limit are still handed over"
	);
}

#[test]
fn an_oversized_header_block_stops_the_walk() {
	let mut raw = b"Content-Type: multipart/mixed; boundary=h\r\n\r\n--h\r\n".to_vec();
	for _ in 0..(MAX_HEADER_BYTES / 20 + 2) {
		raw.extend_from_slice(b"X-Padding: 12345678\r\n");
	}
	raw.extend_from_slice(b"\r\nbody\r\n--h--\r\n");
	let (_, result) = leaves(&raw, &LIMITS);
	assert_eq!(result, Err(Stop::HeaderTooLarge));
}

#[test]
fn past_the_decode_budget_only_a_prefix_is_kept() {
	let big = vec![b'A'; 100_000];
	let raw = corpus::message(&[
		corpus::attachment("Content-Type: application/octet-stream; name=a.bin", &big),
		corpus::attachment("Content-Type: application/octet-stream; name=b.bin", &big),
	]);
	let limits = Limits {
		max_decoded: 150_000,
		..LIMITS
	};
	let (found, _) = leaves(&raw, &limits);
	assert_eq!(found.len(), 3, "the text and two attachments");
	assert_eq!(found[1].content.len(), 100_000);
	assert!(!found[1].truncated);
	assert_eq!(
		found[2].content.len(),
		crate::antispam::attachments::sniff::SNIFF_WINDOW
	);
	assert!(found[2].truncated);
}

#[test]
fn a_base64_encoded_nested_message_is_walked_too() {
	let inner = corpus::message(&[corpus::attachment(
		"Content-Type: application/octet-stream; name=hidden.exe",
		&corpus::pe(),
	)]);
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: message/rfc822; name=fwd.eml",
		&inner,
	)]);
	let (found, result) = leaves(&raw, &LIMITS);
	assert_eq!(result, Ok(6));
	let hidden = found
		.iter()
		.find(|leaf| leaf.filename() == Some("hidden.exe"))
		.expect("the nested attachment is visited");
	assert_eq!(hidden.depth, 3);
	assert!(hidden.content == corpus::pe(), "nested content differs");
}

/// Ten open boundaries of 70 characters, then `lines` lines that each share
/// 69 characters with the innermost one: the costliest near-miss shape.
fn hostile(lines: usize) -> Vec<u8> {
	let mut raw = Vec::new();
	let mut boundaries = Vec::new();
	for level in 0..10 {
		let boundary = format!("{level}{}", "q".repeat(69));
		raw.extend_from_slice(
			format!(
				"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n"
			)
			.as_bytes(),
		);
		boundaries.push(boundary);
	}
	raw.extend_from_slice(b"Content-Type: application/octet-stream; name=x.bin\r\n\r\n");
	let near = format!("--{}\r\n", &boundaries[9][..69]);
	for _ in 0..lines {
		raw.extend_from_slice(near.as_bytes());
	}
	raw
}

#[test]
fn the_cost_stays_linear_on_near_miss_delimiters() {
	let mut per_byte = Vec::new();
	for lines in [2_000, 8_000, 32_000] {
		let raw = hostile(lines);
		STEPS.with(|steps| steps.set(0));
		let (_, result) = leaves(&raw, &LIMITS);
		assert_eq!(result, Ok(11));
		let steps = STEPS.with(|steps| steps.get());
		per_byte.push(steps as f64 / raw.len() as f64);
	}
	for ratio in &per_byte {
		assert!(
			*ratio < 12.0,
			"walk examined {ratio:.1} steps per input byte"
		);
	}
	assert!(
		per_byte[2] < per_byte[0] * 1.2,
		"steps per byte grew with the input: {per_byte:?}"
	);
}

/// `levels` nested multiparts, each followed by a near-miss line for every
/// boundary opened so far: without the depth cap every line would be
/// compared with every open boundary, quadratic in the input.
fn deep_and_hostile(levels: usize) -> Vec<u8> {
	let mut raw = Vec::new();
	for level in 0..levels {
		raw.extend_from_slice(
			format!("Content-Type: multipart/mixed; boundary=\"{level:0>8}\"\r\n\r\n").as_bytes(),
		);
		for _ in 0..8 {
			raw.extend_from_slice(b"--0000000x\r\n");
		}
		raw.extend_from_slice(format!("--{level:0>8}\r\n").as_bytes());
	}
	raw
}

#[test]
fn the_cost_stays_linear_when_nesting_grows_with_the_input() {
	let mut per_byte = Vec::new();
	let mut results = Vec::new();
	for levels in [200, 800, 3_200] {
		let raw = deep_and_hostile(levels);
		STEPS.with(|steps| steps.set(0));
		results.push(leaves(&raw, &LIMITS).1);
		let steps = STEPS.with(|steps| steps.get());
		per_byte.push(steps as f64 / raw.len() as f64);
	}
	assert!(
		per_byte[2] <= per_byte[0],
		"steps per byte grew with the nesting: {per_byte:?}"
	);
	assert_eq!(results, vec![Err(Stop::TooDeep); 3]);
}
