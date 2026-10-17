//! The TimeStampReq (RFC 3161 section 2.4.1) for one SHA-256 digest.
//!
//! The request carries the digest and a random nonce, and asks for the
//! TSA's certificate (`certReq`) so the token verifies on its own. It names
//! no policy and carries no extension: nothing but the digest describes
//! what is being stamped.

use super::der::{encode, encode_all, tag, unsigned_content};
use super::oid;

/// A request and the nonce it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
	/// The DER TimeStampReq.
	pub der: Vec<u8>,
	/// The nonce, to be found again in the token.
	pub nonce: u64,
}

/// The request for `digest` (SHA-256) with `nonce`.
pub fn build(digest: &[u8; 32], nonce: u64) -> Request {
	let algorithm = encode_all(
		tag::SEQUENCE,
		&[&encode(tag::OID, oid::SHA256), &encode(tag::NULL, &[])],
	);
	let imprint = encode_all(
		tag::SEQUENCE,
		&[&algorithm, &encode(tag::OCTET_STRING, digest)],
	);
	let der = encode_all(
		tag::SEQUENCE,
		&[
			&encode(tag::INTEGER, &[1]),
			&imprint,
			&encode(tag::INTEGER, &unsigned_content(nonce)),
			&encode(tag::BOOLEAN, &[0xff]),
		],
	);
	Request { der, nonce }
}

/// A fresh random nonce.
pub fn random_nonce() -> u64 {
	u64::from_be_bytes(
		ring::rand::generate::<[u8; 8]>(&ring::rand::SystemRandom::new())
			.map(|bytes| bytes.expose())
			.unwrap_or_default(),
	)
}
