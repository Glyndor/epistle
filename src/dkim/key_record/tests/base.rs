//! The key type a record declares, the keys it publishes, and the
//! identities it authorizes.

use super::*;
use crate::dkim::signature::Algorithm;

const ED: &str = "3Bmop+ymZ0z/KKff4JzdyvLFAGeLCUOvVvc/fOWX5Vw=";
const RSA: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";

fn record(text: &str) -> KeyRecord {
	parse(text).expect("usable record")
}

#[test]
fn a_record_without_a_k_tag_is_an_rsa_record() {
	assert_eq!(record(&format!("v=DKIM1; p={RSA}")).key_type, KeyType::Rsa);
}

#[test]
fn an_ed25519_record_declares_its_type() {
	assert_eq!(
		record(&format!("v=DKIM1; k=ed25519; p={ED}")).key_type,
		KeyType::Ed25519
	);
}

#[test]
fn an_unknown_key_type_cannot_verify_anything() {
	assert!(parse(&format!("v=DKIM1; k=dsa; p={RSA}")).is_none());
}

#[test]
fn a_revoked_key_cannot_verify_anything() {
	assert!(parse("v=DKIM1; k=ed25519; p=").is_none());
}

#[test]
fn a_record_without_a_key_cannot_verify_anything() {
	assert!(parse("v=DKIM1; k=ed25519").is_none());
}

#[test]
fn a_key_that_is_not_base64_cannot_verify_anything() {
	assert!(parse("v=DKIM1; k=ed25519; p=%%%?").is_none());
}

#[test]
fn the_public_key_is_the_p_tag() {
	assert_eq!(
		record(&format!("v=DKIM1; k=ed25519; p={ED}"))
			.public_key
			.len(),
		32
	);
}

#[test]
fn a_record_fits_only_the_primitive_its_type_declares() {
	let ed = record(&format!("v=DKIM1; k=ed25519; p={ED}"));
	assert!(ed.fits(Algorithm::Ed25519Sha256));
	assert!(!ed.fits(Algorithm::RsaSha256));
	let rsa = record(&format!("v=DKIM1; k=rsa; p={RSA}"));
	assert!(rsa.fits(Algorithm::RsaSha256));
	assert!(!rsa.fits(Algorithm::Ed25519Sha256));
}

#[test]
fn the_record_that_fits_the_signature_is_the_one_picked() {
	let texts = vec![
		"v=DKIM1; k=rsa; p=AAAA".to_string(),
		format!("v=DKIM1; k=ed25519; p={ED}"),
	];
	let picked = select(&texts, Algorithm::Ed25519Sha256).expect("ed25519 record");
	assert_eq!(picked.key_type, KeyType::Ed25519);
}

#[test]
fn no_record_fitting_the_signature_means_no_key() {
	let texts = vec![format!("v=DKIM1; k=ed25519; p={ED}")];
	assert!(select(&texts, Algorithm::RsaSha256).is_none());
}

#[test]
fn a_record_without_the_strict_flag_accepts_a_subdomain_identity() {
	let ed = record(&format!("v=DKIM1; k=ed25519; p={ED}"));
	assert!(!ed.strict_identity);
	assert!(ed.accepts_identity(Some("user@example.test"), "example.test"));
	assert!(ed.accepts_identity(Some("user@child.example.test"), "example.test"));
	assert!(!ed.accepts_identity(Some("user@other.test"), "example.test"));
}

#[test]
fn a_signature_without_an_identity_names_the_signing_domain() {
	let ed = record(&format!("v=DKIM1; k=ed25519; p={ED}"));
	assert!(ed.accepts_identity(None, "example.test"));
}

#[test]
fn the_strict_flag_asks_for_the_signing_domain_exactly() {
	let ed = record(&format!("v=DKIM1; k=ed25519; p={ED}; t=s"));
	assert!(ed.strict_identity);
	assert!(ed.accepts_identity(Some("user@example.test"), "example.test"));
	assert!(!ed.accepts_identity(Some("user@child.example.test"), "example.test"));
}

#[test]
fn the_testing_flag_is_not_the_strict_one() {
	let ed = record(&format!("v=DKIM1; k=ed25519; p={ED}; t=y"));
	assert!(!ed.strict_identity);
}
