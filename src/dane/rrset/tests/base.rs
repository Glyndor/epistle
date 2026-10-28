//! RFC 7672 sections 2.1 and 2.2 per DNS outcome: secure usable, secure
//! unusable, insecure, indeterminate, bogus.

use super::*;

fn answer(validation: Validation, usage: u8, selector: u8, matching_type: u8) -> TlsaAnswer {
	TlsaAnswer {
		validation,
		usage,
		selector,
		matching_type,
		data: vec![7u8; 32],
	}
}

#[test]
fn no_answer_is_absent() {
	assert_eq!(classify(&[]), Ok(TlsaRrset::Absent));
}

#[test]
fn secure_dane_records_are_usable() {
	let rrset = classify(&[
		answer(Validation::Secure, 3, 1, 1),
		answer(Validation::Secure, 2, 0, 2),
	])
	.expect("secure");
	assert_eq!(rrset.records().len(), 2);
}

#[test]
fn a_secure_rrset_keeps_only_its_usable_records() {
	let rrset = classify(&[
		answer(Validation::Secure, 3, 1, 1),
		answer(Validation::Secure, 4, 1, 1),
		answer(Validation::Secure, 1, 1, 1),
	])
	.expect("secure");
	assert_eq!(rrset.records().len(), 1);
	assert_eq!(
		rrset.records()[0].usage,
		crate::dane::tlsa::CertUsage::DaneEe
	);
}

#[test]
fn a_secure_rrset_without_usable_records_is_unusable() {
	for unusable in [
		// Unknown usage, selector, matching type.
		answer(Validation::Secure, 4, 1, 1),
		answer(Validation::Secure, 3, 2, 1),
		answer(Validation::Secure, 3, 1, 3),
		// PKIX-TA and PKIX-EE: RFC 7672 section 3.1.3.
		answer(Validation::Secure, 0, 0, 1),
		answer(Validation::Secure, 1, 1, 1),
	] {
		assert_eq!(
			classify(std::slice::from_ref(&unusable)),
			Ok(TlsaRrset::Unusable),
			"{} {} {}",
			unusable.usage,
			unusable.selector,
			unusable.matching_type
		);
	}
}

#[test]
fn unvalidated_records_do_not_count() {
	for validation in [Validation::Insecure, Validation::Indeterminate] {
		assert_eq!(
			classify(&[answer(validation, 3, 1, 1)]),
			Ok(TlsaRrset::Absent),
			"{validation:?}"
		);
	}
}

#[test]
fn a_bogus_answer_is_a_temporary_failure() {
	assert_eq!(
		classify(&[answer(Validation::Bogus, 3, 1, 1)]),
		Err(DnsFailure::Temporary)
	);
	assert_eq!(
		classify(&[
			answer(Validation::Secure, 3, 1, 1),
			answer(Validation::Bogus, 3, 1, 1),
		]),
		Err(DnsFailure::Temporary)
	);
}
