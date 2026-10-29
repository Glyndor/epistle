//! Keys for the import tests, made when the tests run (ed25519) or taken
//! from the DKIM test key (RSA), so no private key is committed for them.

use base64::Engine;
use ring::signature::Ed25519KeyPair;

fn pem(label: &str, der: &[u8]) -> String {
	let body = base64::engine::general_purpose::STANDARD.encode(der);
	let mut out = format!("-----BEGIN {label}-----\n");
	for chunk in body.as_bytes().chunks(64) {
		out.push_str(std::str::from_utf8(chunk).expect("ascii"));
		out.push('\n');
	}
	out.push_str(&format!("-----END {label}-----\n"));
	out
}

fn der(pem_text: &str) -> Vec<u8> {
	let body: String = pem_text
		.lines()
		.filter(|line| !line.starts_with("-----"))
		.collect();
	base64::engine::general_purpose::STANDARD
		.decode(body)
		.expect("base64")
}

/// A fresh ed25519 key as PKCS#8 version 2 DER.
pub(crate) fn ed25519_v2_der() -> Vec<u8> {
	Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
		.expect("generate")
		.as_ref()
		.to_vec()
}

/// A fresh ed25519 key the way Mox writes it: PKCS#8 version 1, no public
/// key. Returns the PEM and the version 2 DER of the same key.
pub(crate) fn ed25519_v1() -> (String, Vec<u8>) {
	let v2 = ed25519_v2_der();
	let mut v1 = vec![
		0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
		0x20,
	];
	v1.extend_from_slice(&v2[16..48]);
	(pem("PRIVATE KEY", &v1), v2)
}

/// A fresh ed25519 key as PKCS#8 version 2 PEM.
pub(crate) fn ed25519_v2_pem() -> String {
	pem("PRIVATE KEY", &ed25519_v2_der())
}

/// The DKIM test RSA key, PKCS#8 PEM.
pub(crate) fn rsa_pkcs8_pem() -> &'static str {
	include_str!("../../dkim/test_rsa_key.pem")
}

/// The same RSA key as PKCS#1 (`BEGIN RSA PRIVATE KEY`), cut out of the
/// PKCS#8 envelope: the RSAPrivateKey is the last OCTET STRING's content.
pub(crate) fn rsa_pkcs1_pem() -> String {
	let pkcs8 = der(rsa_pkcs8_pem());
	// SEQUENCE header, INTEGER 0, algorithm identifier (15 octets), then
	// the OCTET STRING with a long-form length.
	let header = 2 + usize::from(pkcs8[1] & 0x7f);
	let octet = header + 3 + 15;
	assert_eq!(pkcs8[octet], 0x04, "OCTET STRING");
	let length_octets = usize::from(pkcs8[octet + 1] & 0x7f);
	let start = octet + 2 + length_octets;
	pem("RSA PRIVATE KEY", &pkcs8[start..])
}

/// The PKCS#8 DER of the RSA test key.
pub(crate) fn rsa_pkcs8_der() -> Vec<u8> {
	der(rsa_pkcs8_pem())
}
