//! Exercise AMS and Seal separately so chain failure cannot mask a crypto bug.

use super::harness::*;
use super::support::*;
use epistle::arc::chain::ChainValidation;
use epistle::dkim::DkimOutcome::{Fail, Pass, PermError, TempError};

#[test]
fn external_ed25519_ams_and_seal_pass_separately() {
	let name = "arc-ed-1";
	assert_eq!(ams_result(message(name), Dns::arc(name)), (Pass, 1));
	assert_eq!(seal_result(message(name), Dns::arc(name)), (Pass, 1));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Pass, 2)
	);
}

#[test]
fn external_rsa_ams_passes() {
	let name = "arc-ams-rsa";
	assert_eq!(ams_result(message(name), Dns::arc(name)), (Pass, 1));
}

#[test]
fn external_rsa_seal_passes() {
	let name = "arc-seal-rsa";
	assert_eq!(seal_result(message(name), Dns::arc(name)), (Pass, 1));
}

#[test]
fn external_rsa_chain_passes() {
	let name = "arc-rsa";
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Pass, 2)
	);
}

#[test]
// RFC 6376 section 6.1.2 and RFC 8463 section 4.2 require a usable key
// of the declared algorithm; a type mismatch is a permanent key error.
fn rsa_ams_algorithm_cannot_use_ed25519_key() {
	let name = "arc-ams-rsa-with-ed";
	assert_eq!(ams_result(message(name), Dns::arc(name)), (PermError, 1));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Fail, 1)
	);
}

#[test]
// RFC 6376 section 6.1.2 and RFC 8463 section 4.2 require a usable key
// of the declared algorithm; a type mismatch is a permanent key error.
fn rsa_seal_algorithm_cannot_use_ed25519_key() {
	let name = "arc-seal-rsa-with-ed";
	assert_eq!(seal_result(message(name), Dns::arc(name)), (PermError, 1));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Fail, 2)
	);
}

#[test]
// RFC 6376 section 6.1.2 and RFC 8463 section 4.2 require a usable key
// of the declared algorithm; a type mismatch is a permanent key error.
fn ed25519_ams_algorithm_cannot_use_rsa_key() {
	let name = "arc-ams-ed-with-rsa";
	assert_eq!(ams_result(message(name), Dns::arc(name)), (PermError, 1));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Fail, 1)
	);
}

#[test]
// RFC 6376 section 6.1.2 and RFC 8463 section 4.2 require a usable key
// of the declared algorithm; a type mismatch is a permanent key error.
fn ed25519_seal_algorithm_cannot_use_rsa_key() {
	let name = "arc-seal-ed-with-rsa";
	assert_eq!(seal_result(message(name), Dns::arc(name)), (PermError, 1));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Fail, 2)
	);
}

#[test]
fn seal_does_not_replace_ams_body_check() {
	let name = "arc-ed-1";
	let raw = replace(&message(name), "indented", "attacker");
	assert_eq!(seal_result(raw.clone(), Dns::arc(name)), (Pass, 1));
	assert_eq!(ams_result(raw.clone(), Dns::arc(name)), (Fail, 0));
	assert_eq!(arc(raw, Dns::arc(name)), (ChainValidation::Fail, 0));
}

#[test]
fn ams_with_unsigned_body_hash_cannot_pass() {
	let name = "arc-length-zero";
	assert_eq!(ams_result(message(name), Dns::arc(name)), (Fail, 0));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Fail, 0)
	);
}

#[test]
fn ams_exact_length_hash_covers_the_body() {
	let name = "arc-length-exact";
	assert_eq!(ams_result(message(name), Dns::arc(name)), (Pass, 1));
	assert_eq!(
		arc(message(name), Dns::arc(name)),
		(ChainValidation::Pass, 2)
	);
}

#[test]
fn temporary_dns_is_visible_in_both_crypto_apis() {
	let name = "arc-ed-1";
	let mut dns = Dns::arc(name);
	dns.temporary = true;
	assert_eq!(ams_result(message(name), dns), (TempError, 1));
	let mut dns = Dns::arc(name);
	dns.temporary = true;
	assert_eq!(seal_result(message(name), dns), (TempError, 1));
	let mut dns = Dns::arc(name);
	dns.temporary = true;
	assert_eq!(arc(message(name), dns), (ChainValidation::Fail, 1));
}

#[test]
fn invalid_arc_base64_is_rejected_before_dns() {
	let name = "arc-ed-1";
	let raw = tag(&message(name), "b", "%%%?");
	assert_eq!(arc(raw, Dns::arc(name)), (ChainValidation::Fail, 0));
}

#[test]
fn changed_aar_breaks_the_seal() {
	let name = "arc-ed-1";
	let raw = replace(&message(name), "dkim=pass", "dkim=fail");
	assert_eq!(ams_result(raw.clone(), Dns::arc(name)), (Pass, 1));
	assert_eq!(seal_result(raw.clone(), Dns::arc(name)), (Fail, 1));
	assert_eq!(arc(raw, Dns::arc(name)), (ChainValidation::Fail, 2));
}

#[test]
fn arc_builders_match_external_signatures() {
	bounded(|| {
		use base64::Engine;
		use epistle::arc::{ams, chain, seal};
		let pem = text("ed25519-ring.pem");
		let encoded: String = pem
			.lines()
			.filter(|line| !line.starts_with("-----"))
			.collect();
		let der = base64::engine::general_purpose::STANDARD
			.decode(encoded)
			.unwrap();
		let key = ring::signature::Ed25519KeyPair::from_pkcs8(&der).expect("fixed key");
		let raw = message("arc-build");
		let instances = chain::extract(&raw).unwrap().unwrap();
		let instance = &instances[0];
		let ams =
			ams::build(&key, 1, "example.test", "ams", &message("signer-raw")).expect("build AMS");
		assert_eq!(
			ams.strip_prefix("ARC-Message-Signature:").unwrap().trim(),
			instance.message_signature.trim()
		);
		let params = seal::SealParams {
			instance: 1,
			domain: "example.test",
			selector: "seal",
			chain_validation: ChainValidation::None,
		};
		let seal = seal::build(
			&key,
			&params,
			&[],
			&instance.auth_results,
			&instance.message_signature,
		);
		assert_eq!(
			seal.strip_prefix("ARC-Seal:").unwrap().trim(),
			instance.seal.trim()
		);
	});
}
