use super::*;
use ring::digest;

const LEAF: &[u8] = b"--leaf cert der--";
const LEAF_SPKI: &[u8] = b"--leaf spki--";
const CA: &[u8] = b"--ca cert der--";
const CA_SPKI: &[u8] = b"--ca spki--";

fn sha256(data: &[u8]) -> Vec<u8> {
	digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

fn leaf() -> CertView<'static> {
	CertView::new(LEAF, LEAF_SPKI)
}

fn chain() -> Vec<CertView<'static>> {
	vec![CertView::new(CA, CA_SPKI)]
}

#[test]
fn dane_ee_matches_leaf() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
	assert!(authenticate(&[record], &leaf(), &chain()));
}

#[test]
fn dane_ee_rejects_other_leaf() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"someone else")).expect("record");
	assert!(!authenticate(&[record], &leaf(), &chain()));
}

#[test]
fn dane_ta_matches_chain_certificate() {
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(CA)).expect("record");
	assert!(authenticate(&[record], &leaf(), &chain()));
}

#[test]
fn dane_ta_does_not_match_unrelated_ca() {
	let record = TlsaRecord::from_parts(2, 0, 1, sha256(b"other ca")).expect("record");
	assert!(!authenticate(&[record], &leaf(), &chain()));
}

#[test]
fn any_matching_record_authenticates() {
	let bad = TlsaRecord::from_parts(3, 1, 1, sha256(b"no")).expect("record");
	let good = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
	assert!(authenticate(&[bad, good], &leaf(), &chain()));
}

#[test]
fn no_records_means_not_authenticated() {
	assert!(!authenticate(&[], &leaf(), &chain()));
}

#[test]
fn outcome_authenticated_on_match() {
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
	assert_eq!(
		dane_outcome(&[record], &leaf(), &chain()),
		DaneOutcome::Authenticated
	);
}

#[test]
fn outcome_mismatch_when_no_record_matches() {
	// Records are present (DNSSEC-validated) but none matches the chain:
	// fail closed, the peer is not authenticated.
	let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"wrong key")).expect("record");
	assert_eq!(
		dane_outcome(&[record], &leaf(), &chain()),
		DaneOutcome::Mismatch
	);
}

#[test]
fn outcome_no_records_when_empty() {
	// No validated TLSA: DANE does not apply (opportunistic TLS).
	assert_eq!(dane_outcome(&[], &leaf(), &chain()), DaneOutcome::NoRecords);
}
