use super::*;
use crate::evidence::tsa::fake::{FakeTsa, Faults};
use crate::evidence::tsa::request::build;

/// The digest the captured fixtures stamp: SHA-256 of
/// "epistle evidence fixture\n".
const FIXTURE_DIGEST: &str = "e9769dfadd56fc956eb4dc51373fa4c8763f22efb784b9eb421965ae687ab2db";
/// SHA-256 of the SPKI of "Sectigo Public Time Stamping Root R46".
const SECTIGO_R46: &str = "a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795";
const NOW: u64 = 1_792_038_711;

fn digest() -> [u8; 32] {
	sha256(b"checkpoint bytes")
}

fn stamped(faults: Faults) -> (FakeTsa, Result<Stamp, VerifyError>) {
	let mut tsa = FakeTsa::new(NOW);
	tsa.faults = faults;
	let request = build(&digest(), 77);
	let response = tsa.respond(&request.der);
	let result = verify(&response, &digest(), Some(77), &[tsa.anchor]);
	(tsa, result)
}

#[test]
fn a_good_token_verifies_and_says_when() {
	let (tsa, result) = stamped(Faults::default());
	let stamp = result.expect("verifies");
	assert_eq!(stamp.gen_time, NOW);
	assert_eq!(stamp.anchor, to_hex(&tsa.anchor));
}

#[test]
fn a_token_for_another_digest_is_refused() {
	let (_, result) = stamped(Faults {
		imprint: Some(sha256(b"another checkpoint")),
		..Faults::default()
	});
	assert_eq!(result, Err(VerifyError::Imprint));
}

#[test]
fn a_token_with_another_nonce_is_refused() {
	let (_, result) = stamped(Faults {
		nonce: Some(78),
		..Faults::default()
	});
	assert_eq!(result, Err(VerifyError::Nonce));
}

#[test]
fn a_bad_signature_is_refused() {
	let (_, result) = stamped(Faults {
		bad_signature: true,
		..Faults::default()
	});
	assert_eq!(result, Err(VerifyError::Untrusted("bad signature")));
}

#[test]
fn a_signed_digest_of_something_else_is_refused() {
	let (_, result) = stamped(Faults {
		wrong_message_digest: true,
		..Faults::default()
	});
	assert_eq!(
		result,
		Err(VerifyError::Untrusted(
			"messageDigest does not match the TSTInfo"
		))
	);
}

#[test]
fn a_signer_without_the_timestamping_usage_is_refused() {
	let (_, result) = stamped(Faults {
		no_timestamping: true,
		..Faults::default()
	});
	assert_eq!(
		result,
		Err(VerifyError::Untrusted(
			"the signer has no extended key usage"
		))
	);
}

#[test]
fn a_noncritical_timestamping_usage_is_refused() {
	let (_, result) = stamped(Faults {
		noncritical_timestamping: true,
		..Faults::default()
	});
	assert_eq!(
		result,
		Err(VerifyError::Untrusted(
			"the signer is not a critical timeStamping key"
		))
	);
}

#[test]
fn a_chain_to_an_unpinned_root_is_refused() {
	let tsa = FakeTsa::new(NOW);
	let other = FakeTsa::new(NOW);
	let request = build(&digest(), 1);
	let response = tsa.respond(&request.der);
	assert_eq!(
		verify(&response, &digest(), Some(1), &[other.anchor]),
		Err(VerifyError::Untrusted(
			"the chain does not reach a pinned anchor"
		))
	);
	assert!(verify(&response, &digest(), Some(1), &[other.anchor, tsa.anchor]).is_ok());
}

#[test]
fn a_refusal_is_reported_with_its_status() {
	let (_, result) = stamped(Faults {
		refuse: Some(2),
		..Faults::default()
	});
	assert_eq!(result, Err(VerifyError::Token(TokenError::Refused(2))));
}

#[test]
fn a_signer_outside_its_validity_at_the_stamped_time_is_refused() {
	let mut tsa = FakeTsa::new(1_000);
	tsa.faults = Faults::default();
	let request = build(&digest(), 5);
	let response = tsa.respond(&request.der);
	assert_eq!(
		verify(&response, &digest(), Some(5), &[tsa.anchor]),
		Err(VerifyError::Untrusted(
			"a certificate was not valid at the stamped time"
		))
	);
}

#[test]
fn a_real_sectigo_token_verifies_against_the_pinned_root_key() {
	let response = include_bytes!("testdata/sectigo.tsr");
	let digest = crate::evidence::record::hash_from_hex(FIXTURE_DIGEST).expect("digest");
	let anchor = crate::evidence::record::hash_from_hex(SECTIGO_R46).expect("anchor");
	let stamp = verify(response, &digest, None, &[anchor]).expect("the captured token verifies");
	assert_eq!(stamp.gen_time, 1_792_038_711);
	assert_eq!(stamp.anchor, SECTIGO_R46);
	let mut other = digest;
	other[0] ^= 1;
	assert_eq!(
		verify(response, &other, None, &[anchor]),
		Err(VerifyError::Imprint)
	);
	let mut forged = response.to_vec();
	let last = forged.len() - 1;
	forged[last] ^= 1;
	assert_eq!(
		verify(&forged, &digest, None, &[anchor]),
		Err(VerifyError::Untrusted("bad signature"))
	);
}

#[test]
fn freetsa_tokens_use_a_signature_this_verifier_does_not_support() {
	let response = include_bytes!("testdata/freetsa.tsr");
	let digest = crate::evidence::record::hash_from_hex(FIXTURE_DIGEST).expect("digest");
	assert_eq!(
		verify(response, &digest, None, &[[0; 32]]),
		Err(VerifyError::Untrusted("unsupported signature algorithm"))
	);
}

#[test]
fn every_truncation_of_a_real_token_is_refused_without_panicking() {
	let response = include_bytes!("testdata/sectigo.tsr");
	let digest = crate::evidence::record::hash_from_hex(FIXTURE_DIGEST).expect("digest");
	for length in 0..response.len() {
		assert!(verify(&response[..length], &digest, None, &[[0; 32]]).is_err());
	}
}

#[test]
fn openssl_accepts_the_tokens_the_fake_authority_issues() {
	// The bundle README tells a third party to run `openssl ts -verify`; the
	// fake authority's tokens must pass it like a real authority's do.
	if std::process::Command::new("openssl")
		.arg("version")
		.output()
		.is_err()
	{
		eprintln!(
			"SKIPPED openssl_accepts_the_tokens_the_fake_authority_issues: no openssl on PATH"
		);
		return;
	}
	let tsa = FakeTsa::new(NOW);
	let request = build(&digest(), 9);
	let response = tsa.respond(&request.der);
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join("token.tsr"), &response).expect("token");
	std::fs::write(dir.path().join("root.pem"), tsa.root_pem()).expect("root");
	let run = |digest: &str| {
		std::process::Command::new("openssl")
			.env("OPENSSL_CONF", "/dev/null")
			.args([
				"ts",
				"-verify",
				"-digest",
				digest,
				"-in",
				"token.tsr",
				"-CAfile",
				"root.pem",
			])
			.current_dir(dir.path())
			.output()
			.expect("run openssl")
	};
	let good = run(&to_hex(&digest()));
	assert!(
		String::from_utf8_lossy(&good.stdout).contains("Verification: OK"),
		"openssl refused the token: {}",
		String::from_utf8_lossy(&good.stderr)
	);
	let bad = run(&to_hex(&sha256(b"other")));
	assert!(!String::from_utf8_lossy(&bad.stdout).contains("Verification: OK"));
}
