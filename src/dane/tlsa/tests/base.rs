use super::*;
use ring::digest;

const CERT: &[u8] = b"--fake certificate DER--";
const SPKI: &[u8] = b"--fake subject public key info--";

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn rejects_unknown_field_codes() {
	assert!(TlsaRecord::from_parts(4, 0, 1, vec![1]).is_none());
	assert!(TlsaRecord::from_parts(3, 2, 1, vec![1]).is_none());
	assert!(TlsaRecord::from_parts(3, 1, 3, vec![1]).is_none());
	assert!(TlsaRecord::from_parts(3, 1, 1, vec![]).is_none());
}

#[test]
fn matches_spki_sha256() {
	let data = digest::digest(&digest::SHA256, SPKI).as_ref().to_vec();
	let record = TlsaRecord::from_parts(3, 1, 1, data).expect("record");
	assert!(record.matches_cert(CERT, SPKI));
	// A different SPKI must not match.
	assert!(!record.matches_cert(CERT, b"other key"));
}

#[test]
fn matches_full_cert_sha512() {
	let data = digest::digest(&digest::SHA512, CERT).as_ref().to_vec();
	let record = TlsaRecord::from_parts(2, 0, 2, data).expect("record");
	assert!(record.matches_cert(CERT, SPKI));
}

#[test]
fn matches_full_exact() {
	let record = TlsaRecord::from_parts(3, 1, 0, SPKI.to_vec()).expect("record");
	assert!(record.matches_cert(CERT, SPKI));
	assert!(!record.matches_cert(CERT, b"nope"));
}

#[test]
fn parses_presentation_form() {
	let data = digest::digest(&digest::SHA256, SPKI).as_ref().to_vec();
	let text = format!("3 1 1 {}", hex(&data));
	let record = TlsaRecord::parse_presentation(&text).expect("parsed");
	assert_eq!(record.usage, CertUsage::DaneEe);
	assert_eq!(record.selector, Selector::Spki);
	assert_eq!(record.matching_type, MatchingType::Sha256);
	assert!(record.matches_cert(CERT, SPKI));
}

#[test]
fn parses_presentation_with_split_hex() {
	let data = digest::digest(&digest::SHA256, SPKI).as_ref().to_vec();
	let half = hex(&data);
	let (a, b) = half.split_at(20);
	let text = format!("3 1 1 {a} {b}");
	let record = TlsaRecord::parse_presentation(&text).expect("parsed");
	assert!(record.matches_cert(CERT, SPKI));
}

#[test]
fn rejects_malformed_presentation() {
	assert!(TlsaRecord::parse_presentation("3 1 1").is_none());
	assert!(TlsaRecord::parse_presentation("3 1 1 xyz").is_none());
	assert!(TlsaRecord::parse_presentation("9 1 1 aabb").is_none());
}
