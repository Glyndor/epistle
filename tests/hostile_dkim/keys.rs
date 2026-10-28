//! DNS key metadata and algorithm boundaries, all signatures external.

use super::harness::*;
use epistle::dkim::DkimOutcome::{Fail, Pass};
use epistle::dkim::Signer;

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
