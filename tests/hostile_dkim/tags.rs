//! Exact tag-list outcomes (RFC 6376 sections 3.2, 3.6.1 and 6.1.2).
//! Every DNS mutation preserves a signed message and first checks its valid DNS.
//! Signature duplicates were included before signing, never patched afterwards.

use super::harness::*;
use epistle::dkim::DkimOutcome::{self, Pass, PermError};

const OWNER: &str = "tags._domainkey.example.org";

fn fixture(name: &str, outcome: DkimOutcome) {
	expect_dkim(
		message(name),
		Dns::one(OWNER, &record(name)),
		outcome,
		Some("example.org"),
		1,
	);
}

fn dns_case(name: &str, baseline: &str, outcome: DkimOutcome) {
	assert_eq!(message(name), message(baseline), "only DNS may change");
	assert_ne!(record(name), record(baseline), "DNS mutation must differ");
	fixture(baseline, Pass);
	fixture(name, outcome);
}

fn signature_error(name: &str) {
	assert_eq!(record(name), record("tags-rsa"), "DNS must stay valid");
	fixture("tags-rsa", Pass);
	expect_dkim(
		message(name),
		Dns::one(OWNER, &record(name)),
		PermError,
		None,
		0,
	);
}

#[test]
fn rsa_control_passes() {
	fixture("tags-rsa", Pass);
}

#[test]
fn ed25519_control_passes() {
	fixture("tags-ed", Pass);
}

#[test]
fn subdomain_identity_control_passes() {
	fixture("tags-subdomain", Pass);
}

#[test]
fn valid_p_then_empty_p_is_permerror() {
	dns_case("tags-p-valid-empty", "tags-rsa", PermError);
}

#[test]
fn empty_p_then_valid_p_is_permerror() {
	dns_case("tags-p-empty-valid", "tags-rsa", PermError);
}

#[test]
fn strict_then_testing_duplicate_t_is_permerror() {
	dns_case("tags-t-s-y", "tags-subdomain", PermError);
}

#[test]
fn testing_then_strict_duplicate_t_is_permerror() {
	dns_case("tags-t-y-s", "tags-subdomain", PermError);
}

#[test]
fn duplicate_rsa_then_ed25519_k_is_permerror() {
	dns_case("tags-k-rsa-ed", "tags-rsa", PermError);
}

#[test]
fn duplicate_signature_i_is_permerror_before_dns() {
	signature_error("tags-i-duplicate");
}

#[test]
fn duplicate_unknown_dns_tag_is_permerror() {
	dns_case("tags-unknown-dns-duplicate", "tags-rsa", PermError);
}

#[test]
fn duplicate_unknown_signature_tag_is_permerror_before_dns() {
	signature_error("tags-unknown-signature-duplicate");
}

#[test]
fn unsupported_dns_version_is_permerror() {
	dns_case("tags-version2", "tags-rsa", PermError);
}

#[test]
fn sha1_only_key_cannot_authorize_sha256() {
	dns_case("tags-hash-sha1", "tags-rsa", PermError);
}

#[test]
fn other_service_key_is_permerror_for_email() {
	dns_case("tags-service-other", "tags-rsa", PermError);
}

#[test]
fn email_service_key_passes() {
	dns_case("tags-service-email", "tags-rsa", Pass);
}

#[test]
fn wildcard_service_key_passes() {
	dns_case("tags-service-all", "tags-rsa", Pass);
}

#[test]
fn ed25519_declared_with_rsa_material_is_permerror() {
	dns_case("tags-ed-rsa-material", "tags-ed", PermError);
}

#[test]
fn rsa_declared_with_ed25519_material_is_permerror() {
	dns_case("tags-rsa-ed-material", "tags-rsa", PermError);
}

#[test]
fn single_unknown_dns_tag_is_ignored() {
	dns_case("tags-unknown-dns-single", "tags-rsa", Pass);
}

#[test]
fn single_unknown_signature_tag_is_ignored() {
	fixture("tags-unknown-signature-single", Pass);
}

#[test]
fn sha256_authorized_key_passes() {
	dns_case("tags-hash-sha256", "tags-rsa", Pass);
}
