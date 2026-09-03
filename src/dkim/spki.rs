//! DKIM RSA SubjectPublicKeyInfo encoding.
//!
//! DKIM's `p=` value is the base64 of an X.509 SubjectPublicKeyInfo DER
//! block, not the bare PKCS#1 `RSAPublicKey` body that
//! `ring::signature::RsaKeyPair::public_key()` returns. The SPKI envelope
//! is fixed for rsaEncryption (OID `1.2.840.113549.1.1.1`, NULL
//! parameters), so we build it by hand and skip an ASN.1 crate. The
//! outbound signer and the CLI keygen path both feed the same body in
//! and expect the same envelope out, which is why [`spki_for_rsa`] is
//! `pub(crate)` and why the test in `spki_tests.rs` round-trips it
//! against `openssl rsa -pubout`.

/// Wrap an RSAPublicKey DER body in the SubjectPublicKeyInfo envelope
/// (RFC 5958 / RFC 3279 §2.3.1) that DKIM's `p=` value uses. The envelope
/// is fixed for rsaEncryption: an `AlgorithmIdentifier` with OID
/// `1.2.840.113549.1.1.1` and `NULL` parameters, then a `BIT STRING`
/// containing the key. `ring`'s `RsaKeyPair::public_key()` returns the
/// inner PKCS#1 body, so we prepend the fixed envelope by hand instead of
/// pulling in an ASN.1 crate.
pub(crate) fn spki_for_rsa(pkcs1: &[u8]) -> Vec<u8> {
	rsa_spki_der(pkcs1)
}

/// Build the SubjectPublicKeyInfo DER from a PKCS#1 RSAPublicKey body.
/// The envelope is fixed for rsaEncryption (OID `1.2.840.113549.1.1.1`,
/// NULL parameters) so the same algorithm identifier is reused on every
/// call.
pub(crate) fn rsa_spki_der(pkcs1: &[u8]) -> Vec<u8> {
	let algorithm_identifier: &[u8] = &[
		0x30, 0x0D, // SEQUENCE { AlgorithmIdentifier }
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
		0x01, // OID 1.2.840.113549.1.1.1
		0x05, 0x00, // NULL parameters
	];
	let mut bit_string = Vec::with_capacity(pkcs1.len() + 3);
	bit_string.push(0x03); // BIT STRING tag
	der_append_len(&mut bit_string, pkcs1.len() + 1);
	bit_string.push(0x00); // zero unused bits
	bit_string.extend_from_slice(pkcs1);

	let mut subject_public_key_info =
		Vec::with_capacity(algorithm_identifier.len() + bit_string.len() + 2);
	subject_public_key_info.push(0x30); // SEQUENCE
	der_append_len(
		&mut subject_public_key_info,
		algorithm_identifier.len() + bit_string.len(),
	);
	subject_public_key_info.extend_from_slice(algorithm_identifier);
	subject_public_key_info.extend_from_slice(&bit_string);
	subject_public_key_info
}

/// Append a DER length to `out`, encoding the value in the short form
/// (single byte, MSB clear) when it fits in seven bits and the long form
/// otherwise. RFC 5280 §4.1 defines the encoding.
pub(crate) fn der_append_len(out: &mut Vec<u8>, len: usize) {
	if len < 0x80 {
		out.push(len as u8);
		return;
	}
	let bytes = len.to_be_bytes();
	let skip = bytes.iter().position(|&b| b != 0).unwrap_or(0);
	let body = &bytes[skip..];
	out.push(0x80 | body.len() as u8);
	out.extend_from_slice(body);
}

#[cfg(test)]
#[path = "spki_tests.rs"]
mod tests;
