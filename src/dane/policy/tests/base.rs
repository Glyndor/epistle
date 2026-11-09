use super::*;
use ring::digest;

const LEAF: &[u8] = b"--leaf cert der--";
const LEAF_SPKI: &[u8] = b"--leaf spki--";
const CA: &[u8] = b"--ca cert der--";
const CA_SPKI: &[u8] = b"--ca spki--";
const MX: &str = "mx.example.org";

fn sha256(data: &[u8]) -> Vec<u8> {
	digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

fn leaf() -> CertView<'static> {
	CertView::new(LEAF, LEAF_SPKI)
}

fn chain() -> Vec<CertView<'static>> {
	vec![CertView::new(CA, CA_SPKI)]
}

/// A certificate of a test chain: its DER and its SPKI.
struct Cert {
	der: Vec<u8>,
	spki: Vec<u8>,
}

impl Cert {
	fn view(&self) -> CertView<'_> {
		CertView::new(&self.der, &self.spki)
	}
}

/// The DER and the SPKI of a certificate.
fn cert(certificate: &rcgen::Certificate) -> Cert {
	Cert {
		der: certificate.der().to_vec(),
		spki: crate::dane::cert::spki_of(certificate.der()).expect("spki"),
	}
}

/// A CA certificate and a leaf it signed for the MX host.
fn signed_chain() -> (Cert, Cert) {
	let ca_key = rcgen::KeyPair::generate().expect("ca key");
	let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
	ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
	let ca = ca_params.self_signed(&ca_key).expect("ca cert");
	let issuer = rcgen::Issuer::new(ca_params, ca_key);
	let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
	let leaf_params = rcgen::CertificateParams::new(vec![MX.to_string()]).expect("leaf params");
	let leaf = leaf_params
		.signed_by(&leaf_key, &issuer)
		.expect("leaf cert");
	(cert(&ca), cert(&leaf))
}

#[test]
fn dane_ee_matches_leaf() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
	assert!(authenticate(&[record], &leaf(), &chain(), MX));
}

#[test]
fn dane_ee_rejects_other_leaf() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"someone else")).expect("record");
	assert!(!authenticate(&[record], &leaf(), &chain(), MX));
}

#[test]
fn dane_ta_authenticates_a_chain_that_reaches_the_anchor() {
	let (ca, leaf) = signed_chain();
	// 2 0 1: DANE-TA, full-certificate selector, SHA-256 of the anchor.
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(&ca.der)).expect("record");
	assert!(authenticate(&[record], &leaf.view(), &[ca.view()], MX));
}

#[test]
fn dane_ta_authenticates_with_the_anchor_the_record_carries() {
	let (ca, leaf) = signed_chain();
	// 2 0 0: DANE-TA, full-certificate selector, full certificate. The record
	// carries the anchor and the peer presented only the leaf.
	let record = TlsaRecord::from_parts(2, 0, 0, ca.der.clone()).expect("record");
	assert!(authenticate(&[record], &leaf.view(), &[], MX));
}

#[test]
fn dane_ta_rejects_a_leaf_that_is_not_valid_for_the_name() {
	let (ca, leaf) = signed_chain();
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(&ca.der)).expect("record");
	assert!(!authenticate(
		&[record],
		&leaf.view(),
		&[ca.view()],
		"other.example.org"
	));
}

#[test]
fn dane_ta_digest_of_an_anchor_that_was_not_presented_does_not_authenticate() {
	let (ca, leaf) = signed_chain();
	// The record pins the anchor by digest, but the peer did not present it:
	// a digest does not rebuild the certificate, so it authenticates nothing.
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(&ca.der)).expect("record");
	assert!(!authenticate(&[record], &leaf.view(), &[], MX));
}

#[test]
fn dane_ta_rejects_a_chain_that_does_not_reach_the_anchor() {
	let (ca, _) = signed_chain();
	// A leaf that the anchor did not sign: the anchor is presented, but the
	// chain does not lead to it.
	let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
	let leaf_params = rcgen::CertificateParams::new(vec![MX.to_string()]).expect("leaf params");
	let leaf = leaf_params.self_signed(&leaf_key).expect("leaf cert");
	let leaf = cert(&leaf);
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(&ca.der)).expect("record");
	assert!(!authenticate(&[record], &leaf.view(), &[ca.view()], MX));
}

#[test]
fn dane_ta_does_not_match_unrelated_ca() {
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(b"other ca")).expect("record");
	assert!(!authenticate(&[record], &leaf(), &chain(), MX));
}

#[test]
fn any_matching_record_authenticates() {
	let bad = TlsaRecord::from_parts(3, 1, 1, sha256(b"no")).expect("record");
	let good = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
	assert!(authenticate(&[bad, good], &leaf(), &chain(), MX));
}

#[test]
fn no_records_means_not_authenticated() {
	assert!(!authenticate(&[], &leaf(), &chain(), MX));
}

#[test]
fn outcome_authenticated_on_match() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
	assert_eq!(
		dane_outcome(&[record], &leaf(), &chain(), MX),
		DaneOutcome::Authenticated
	);
}

#[test]
fn outcome_mismatch_when_no_record_matches() {
	// Records are present (DNSSEC-validated) but none matches the chain:
	// fail closed, the peer is not authenticated.
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"wrong key")).expect("record");
	assert_eq!(
		dane_outcome(&[record], &leaf(), &chain(), MX),
		DaneOutcome::Mismatch
	);
}

#[test]
fn outcome_no_records_when_empty() {
	// No validated TLSA: DANE does not apply (opportunistic TLS).
	assert_eq!(
		dane_outcome(&[], &leaf(), &chain(), MX),
		DaneOutcome::NoRecords
	);
}
