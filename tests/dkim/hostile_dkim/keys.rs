//! DNS key metadata and algorithm boundaries, all signatures external.

use super::harness::*;
use epistle::dkim::DkimOutcome::{Fail, Pass, PermError, TempError};
use epistle::dkim::Signer;

const ED: &str = "ed25519-relaxed-relaxed-mixed";
const RSA: &str = "rsa2048-relaxed-relaxed-mixed";

fn dns(value: &str) -> Dns {
	Dns::one("external._domainkey.example.test", value)
}

#[test]
fn absent_rsa_k_uses_the_rsa_default() {
	let record = record(RSA).replace(" k=rsa;", "");
	expect_dkim(message(RSA), dns(&record), Pass, Some("example.test"), 1);
}

#[test]
fn absent_k_is_not_an_ed25519_default() {
	let record = record(ED).replace(" k=ed25519;", "");
	expect_dkim(
		message(ED),
		dns(&record),
		PermError,
		Some("example.test"),
		1,
	);
}

#[test]
fn revoked_key_is_permerror() {
	expect_dkim(
		message(ED),
		dns("v=DKIM1; k=ed25519; p="),
		PermError,
		Some("example.test"),
		1,
	);
}

#[test]
fn missing_key_is_permerror() {
	expect_dkim(
		message(ED),
		dns("v=DKIM1; k=ed25519"),
		PermError,
		Some("example.test"),
		1,
	);
}

#[test]
fn temporary_dns_is_temperror() {
	let mut dns = Dns::dkim(ED);
	dns.temporary = true;
	expect_dkim(message(ED), dns, TempError, Some("example.test"), 1);
}

#[test]
fn testing_flag_still_reports_the_cryptographic_result() {
	let value = format!("{}; t=y", record(ED));
	expect_dkim(message(ED), dns(&value), Pass, Some("example.test"), 1);
	let raw = replace(&message(ED), "indented", "attacker");
	expect_dkim(raw, dns(&value), Fail, Some("example.test"), 0);
}

#[test]
fn strict_identity_flag_accepts_default_same_domain_identity() {
	let value = format!("{}; t=s", record(ED));
	expect_dkim(message(ED), dns(&value), Pass, Some("example.test"), 1);
}

#[test]
fn subdomain_identity_passes_without_strict_flag() {
	case("identity-subdomain", Pass, 1);
}

#[test]
fn strict_identity_flag_rejects_subdomain_identity() {
	let value = format!("{}; t=s", record("identity-subdomain"));
	expect_dkim(
		message("identity-subdomain"),
		dns(&value),
		PermError,
		Some("example.test"),
		1,
	);
}

#[test]
fn rsa_512_is_rejected() {
	case("rsa512", Fail, 1);
}

#[test]
fn rsa_1024_interoperability() {
	case("rsa1024", Pass, 1);
}

#[test]
fn the_signer_refuses_an_rsa_key_below_2048_bits() {
	let signer = Signer::load("external", &path("ed25519-ring.pem")).expect("ed25519 key");
	assert!(signer.with_rsa("external", &path("rsa1024.pem")).is_err());
}

#[test]
fn declared_rsa_key_type_cannot_authorize_ed25519() {
	let value = record(ED).replace("k=ed25519", "k=rsa");
	expect_dkim(message(ED), dns(&value), PermError, Some("example.test"), 1);
}

#[test]
fn declared_ed25519_key_type_cannot_authorize_rsa() {
	let value = record(RSA).replace("k=rsa", "k=ed25519");
	expect_dkim(
		message(RSA),
		dns(&value),
		PermError,
		Some("example.test"),
		1,
	);
}

#[test]
fn rsa_algorithm_with_an_ed25519_key_is_a_permerror() {
	case("rsa-with-ed-key", PermError, 1);
}

#[test]
fn ed25519_algorithm_with_an_rsa_key_is_a_permerror() {
	case("ed-with-rsa-key", PermError, 1);
}
