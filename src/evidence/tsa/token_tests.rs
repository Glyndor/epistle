use super::*;
use crate::evidence::tsa::der::unsigned_content;
use crate::evidence::tsa::der::{encode, encode_all};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

#[test]
fn a_response_is_taken_apart() {
	let tsa = FakeTsa::new(1_792_038_711);
	let nonce = random_nonce();
	let digest = crate::evidence::record::sha256(b"stamped");
	let request = build(&digest, nonce);
	let response = tsa.respond(&request.der);
	let token = parse_response(&response).expect("token");
	assert_eq!(token.tst.hashed_message, &digest);
	assert_eq!(token.tst.hash_algorithm, oid::SHA256);
	assert_eq!(token.tst.gen_time, 1_792_038_711);
	assert_eq!(token.tst.nonce, Some(unsigned_content(nonce).as_slice()));
	assert_eq!(token.certificates.len(), 2);
	assert_eq!(
		token
			.signer
			.certificate_hash
			.map(|(algorithm, _)| algorithm),
		Some(oid::SHA256)
	);
	assert_eq!(token.signer.content_type, Some(oid::TST_INFO));
}

#[test]
fn oversized_and_overfull_responses_are_refused() {
	assert_eq!(
		parse_response(&vec![0u8; MAX_RESPONSE + 1]),
		Err(TokenError::Shape("response too large"))
	);
	let status = encode_all(tag::SEQUENCE, &[&encode(tag::INTEGER, &[0])]);
	let certificate = encode(tag::SEQUENCE, &[]);
	let many: Vec<&[u8]> =
		std::iter::repeat_n(certificate.as_slice(), MAX_CERTIFICATES + 1).collect();
	let signed_data = encode_all(
		tag::SEQUENCE,
		&[
			&encode(tag::INTEGER, &[3]),
			&encode(tag::SET, &[]),
			&encode_all(
				tag::SEQUENCE,
				&[
					&encode(tag::OID, oid::TST_INFO),
					&encode(
						tag::CONTEXT_0,
						&encode(
							tag::OCTET_STRING,
							&encode_all(
								tag::SEQUENCE,
								&[
									&encode(tag::INTEGER, &[1]),
									&encode(tag::OID, &[0x2a]),
									&encode_all(
										tag::SEQUENCE,
										&[
											&encode_all(
												tag::SEQUENCE,
												&[&encode(tag::OID, oid::SHA256)],
											),
											&encode(tag::OCTET_STRING, &[0; 32]),
										],
									),
									&encode(tag::INTEGER, &[1]),
									&encode(tag::GENERALIZED_TIME, b"20261015043151Z"),
								],
							),
						),
					),
				],
			),
			&encode_all(tag::CONTEXT_0, &many),
		],
	);
	let content_info = encode_all(
		tag::SEQUENCE,
		&[
			&encode(tag::OID, oid::SIGNED_DATA),
			&encode(tag::CONTEXT_0, &signed_data),
		],
	);
	let response = encode_all(tag::SEQUENCE, &[&status, &content_info]);
	assert_eq!(
		parse_response(&response),
		Err(TokenError::Shape("too many certificates"))
	);
}

#[test]
fn deep_nesting_is_not_followed() {
	// A thousand nested SEQUENCEs: the parser reads the shape it expects and
	// stops at the first element that does not fit, without recursion.
	let mut nested = encode(tag::INTEGER, &[0]);
	for _ in 0..1000 {
		nested = encode(tag::SEQUENCE, &nested);
	}
	assert!(parse_response(&nested).is_err());
}
