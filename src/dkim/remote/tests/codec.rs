//! The frame codec on its own: what it accepts, what it refuses, and that
//! a length is checked before anything is allocated for it.

use super::*;
use crate::dkim::HeaderBlock;
use crate::dkim::remote::frame::{
	FrameError, MAX_CANONICAL_BYTES, MAX_DOMAIN_BYTES, MAX_REQUEST_BYTES, OP_SIGN_DKIM, ReadError,
	SignRequest, read_frame,
};

fn plain_request() -> SignRequest {
	let (names, canonical, body_hash) = plain_fields();
	SignRequest {
		domain: "example.org".into(),
		block: HeaderBlock {
			names,
			canonical,
			body_hash,
		},
	}
}

#[test]
fn a_request_and_every_answer_survive_the_round_trip() {
	let request = plain_request();
	let frame = request.encode().expect("encodes");
	assert_eq!(SignRequest::decode(&frame[4..]), Ok(request));

	let mut answers = vec![SignResponse::Signed("DKIM-Signature: v=1\r\n".into())];
	answers.extend(
		(0..=u8::MAX)
			.filter_map(Reason::from_byte)
			.map(SignResponse::Refused),
	);
	assert_eq!(answers.len(), 8, "seven reasons and the signature");
	for answer in answers {
		assert_eq!(decode_answer(&answer.encode()), answer);
	}
}

#[test]
fn every_truncation_of_a_request_is_refused_and_the_whole_one_is_not() {
	let frame = plain_request().encode().expect("encodes");
	let body = &frame[4..];
	assert!(SignRequest::decode(body).is_ok());
	for end in 0..body.len() {
		assert_eq!(
			SignRequest::decode(&body[..end]),
			Err(FrameError::Truncated),
			"cut at {end}"
		);
	}
	let mut trailing = body.to_vec();
	trailing.push(0);
	assert_eq!(SignRequest::decode(&trailing), Err(FrameError::Trailing));
}

#[test]
fn each_field_is_refused_one_byte_over_its_cap_and_taken_at_it() {
	let (names, canonical, hash) = plain_fields();
	let at_cap = format!("{}.org", "a".repeat(MAX_DOMAIN_BYTES - 4));
	let over_cap = format!("{at_cap}x");
	let with = |domain: &str| {
		body(
			VERSION,
			OP_SIGN_DKIM,
			&[
				domain.as_bytes(),
				names.as_bytes(),
				canonical.as_bytes(),
				&hash,
			],
		)
	};
	assert_eq!(
		SignRequest::decode(&with(&at_cap)).map(|request| request.domain),
		Ok(at_cap.clone())
	);
	assert_eq!(
		SignRequest::decode(&with(&over_cap)),
		Err(FrameError::TooLong)
	);

	let short_hash = body(
		VERSION,
		OP_SIGN_DKIM,
		&[
			b"example.org",
			names.as_bytes(),
			canonical.as_bytes(),
			&hash[..31],
		],
	);
	assert_eq!(SignRequest::decode(&short_hash), Err(FrameError::BodyHash));
	let long_hash = body(
		VERSION,
		OP_SIGN_DKIM,
		&[
			b"example.org",
			names.as_bytes(),
			canonical.as_bytes(),
			&[0; 33],
		],
	);
	assert_eq!(SignRequest::decode(&long_hash), Err(FrameError::TooLong));

	let latin1 = body(
		VERSION,
		OP_SIGN_DKIM,
		&[
			b"ex\xe9mple.org",
			names.as_bytes(),
			canonical.as_bytes(),
			&hash,
		],
	);
	assert_eq!(SignRequest::decode(&latin1), Err(FrameError::NotUtf8));
}

#[test]
fn the_version_is_read_before_the_operation_and_both_before_the_fields() {
	assert_eq!(SignRequest::decode(&[2, 9]), Err(FrameError::Version(2)));
	assert_eq!(
		SignRequest::decode(&[VERSION, 9]),
		Err(FrameError::Operation(9))
	);
	assert_eq!(
		SignRequest::decode(&[VERSION, OP_SIGN_DKIM]),
		Err(FrameError::Truncated)
	);
}

#[test]
fn the_client_never_encodes_a_request_over_the_caps() {
	let mut request = plain_request();
	request.block.canonical = "a".repeat(MAX_CANONICAL_BYTES + 1);
	assert_eq!(request.encode(), Err(FrameError::TooLong));
	request.block.canonical = "a".repeat(MAX_CANONICAL_BYTES);
	let frame = request.encode().expect("at the cap");
	assert!(frame.len() - 4 <= MAX_REQUEST_BYTES);
}

#[test]
fn an_answer_with_an_unknown_status_or_reason_is_refused() {
	let refused = |reason: &[u8]| body(VERSION, 1, &[reason]);
	assert_eq!(
		SignResponse::decode(&refused(&[0])),
		Err(FrameError::Status(0))
	);
	assert_eq!(
		SignResponse::decode(&refused(&[99])),
		Err(FrameError::Status(99))
	);
	assert_eq!(
		SignResponse::decode(&refused(&[5, 5])),
		Err(FrameError::TooLong)
	);
	assert_eq!(
		SignResponse::decode(&refused(&[5])),
		Ok(SignResponse::Refused(Reason::Domain))
	);
	assert_eq!(
		SignResponse::decode(&body(VERSION, 7, &[])),
		Err(FrameError::Status(7))
	);
	assert_eq!(
		SignResponse::decode(&body(2, 0, &[b"x"])),
		Err(FrameError::Version(2))
	);
}

#[tokio::test]
async fn a_length_over_the_cap_is_refused_before_the_rest_arrives() {
	let (mut writer, mut reader) = tokio::io::duplex(64);
	// Only the prefix is ever written: a reader that waited for the body,
	// or allocated it, would sit here until the timeout below fails it.
	writer
		.write_all(&u32::MAX.to_be_bytes())
		.await
		.expect("prefix");
	let read = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		read_frame(&mut reader, MAX_REQUEST_BYTES),
	)
	.await
	.expect("refused without waiting for the body");
	assert!(
		matches!(read, Err(ReadError::TooLarge(u32::MAX))),
		"{read:?}"
	);

	let (mut writer, mut reader) = tokio::io::duplex(64);
	writer.write_all(&framed(b"abc")).await.expect("frame");
	let read = read_frame(&mut reader, 3).await.expect("at the cap");
	assert_eq!(read, b"abc");
}
