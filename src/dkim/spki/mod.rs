//! DKIM RSA SubjectPublicKeyInfo encoding.
//!
//! DKIM's `p=` value is the base64 of an X.509 SubjectPublicKeyInfo DER
//! block, not the bare PKCS#1 `RSAPublicKey` body that
//! `ring::signature::RsaKeyPair::public_key()` returns. The SPKI envelope
//! is fixed for rsaEncryption (OID `1.2.840.113549.1.1.1`, NULL
//! parameters), so we build it by hand and skip an ASN.1 crate. The
//! outbound signer and the CLI keygen path both feed the same body in
//! and expect the same envelope out, which is why [`spki_for_rsa`] is
//! `pub(crate)` and why the test in `src/dkim/spki/tests/base.rs` round-trips it
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

/// The PKCS#1 `RSAPublicKey` inside a SubjectPublicKeyInfo for
/// rsaEncryption, or `None` when `der` is not one. A DKIM `k=rsa` record
/// carries the SPKI (RFC 6376 §3.6.1), and ring verifies against the bare
/// `RSAPublicKey`, so the verifier unwraps it first. Only definite-length
/// DER is read, every length is checked against what is left, and nothing
/// may follow the structure.
pub(crate) fn rsa_public_key_from_spki(der: &[u8]) -> Option<&[u8]> {
	const RSA_ENCRYPTION: &[u8] = &[
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
	];
	let (spki, rest) = der_take(der, 0x30)?;
	if !rest.is_empty() {
		return None;
	}
	let (algorithm, rest) = der_take(spki, 0x30)?;
	let parameters = algorithm.strip_prefix(RSA_ENCRYPTION)?;
	if !(parameters.is_empty() || parameters == [0x05, 0x00]) {
		return None;
	}
	let (bits, rest) = der_take(rest, 0x03)?;
	if !rest.is_empty() {
		return None;
	}
	let (&unused, key) = bits.split_first()?;
	(unused == 0 && !key.is_empty()).then_some(key)
}

/// The bit length of the modulus of a PKCS#1 `RSAPublicKey` body, or `None`
/// when the body is not that structure.
///
/// The body is `SEQUENCE { modulus INTEGER, publicExponent INTEGER }`, so
/// the modulus is the first element of the sequence. A DER integer carries
/// a leading zero byte when its top bit is set, and that byte is not part of
/// the modulus.
pub(crate) fn rsa_modulus_bits(pkcs1: &[u8]) -> Option<usize> {
	let (sequence, rest) = der_take(pkcs1, 0x30)?;
	if !rest.is_empty() {
		return None;
	}
	let (modulus, _) = der_take(sequence, 0x02)?;
	let modulus = if modulus.first() == Some(&0) {
		&modulus[1..]
	} else {
		modulus
	};
	let top = modulus.first()?;
	Some(modulus.len() * 8 - top.leading_zeros() as usize)
}

/// Split one DER element with tag `tag` off the front of `der`, returning
/// its contents and what follows it.
fn der_take(der: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
	let (&first, rest) = der.split_first()?;
	if first != tag {
		return None;
	}
	let (&len_byte, rest) = rest.split_first()?;
	let (len, rest) = if len_byte < 0x80 {
		(usize::from(len_byte), rest)
	} else {
		let count = usize::from(len_byte & 0x7F);
		if count == 0 || count > 4 || rest.len() < count {
			return None;
		}
		let (bytes, rest) = rest.split_at(count);
		let len = bytes
			.iter()
			.fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
		(len, rest)
	};
	(rest.len() >= len).then(|| rest.split_at(len))
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
mod tests;
