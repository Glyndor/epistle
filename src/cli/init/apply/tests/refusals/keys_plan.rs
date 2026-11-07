//! The plan-phase refusals: `plan` must refuse the same key shapes the
//! apply phase refuses, before the operator confirms anything.

use super::super::helpers::errors::{answers_minimal, apply_error_name};
use super::*;

/// Non-UTF-8 bytes in the surviving oauth private key must surface
/// as `OAuthPairIncomplete` from the plan so the operator sees the
/// refusal before confirming. The plan validates the pair before
/// any effect, exactly the way the apply phase does.
#[test]
fn plan_refuses_oauth_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_signing.key"), bad).expect("write bad private");
	std::fs::write(keys_dir.join("oauth_public.key"), b"public").expect("write public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse non-utf-8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!(
			"expected OAuthPairIncomplete, got {}",
			apply_error_name(&err)
		);
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem"
	);
}

/// Non-UTF-8 bytes in the surviving oauth public key must surface
/// as `OAuthPairIncomplete` from the plan. Without the explicit
/// utf-8 check, the trim comparison would misreport the
/// mismatch as `OAuthPairMismatch` and the operator would not see
/// the real cause. The private key must therefore be a real
/// PKCS#8 ES256 document so the plan reaches the public-half
/// utf-8 check.
#[test]
fn plan_refuses_oauth_public_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "mint: {:?}", outcome.error);
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_public.key"), bad).expect("write bad public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse non-utf-8 oauth public");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!(
			"expected OAuthPairIncomplete, got {}",
			apply_error_name(&err)
		);
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem on the public half"
	);
}

/// A surviving oauth private key that is utf-8 but not a valid
/// PKCS#8 ES256 document must surface as `OAuthPairIncomplete`
/// from the plan with the "not a valid PKCS#8" wording, not as
/// the more generic `OAuthPairMismatch`.
#[test]
fn plan_refuses_oauth_private_key_that_is_not_a_pkcs8_es256_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	std::fs::write(keys_dir.join("oauth_signing.key"), b"definitely not a key")
		.expect("write private");
	std::fs::write(keys_dir.join("oauth_public.key"), b"public").expect("write public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse a non-PKCS#8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!(
			"expected OAuthPairIncomplete, got {}",
			apply_error_name(&err)
		);
	};
	assert!(
		message.contains("PKCS#8"),
		"the diagnostic must name the PKCS#8 problem"
	);
}

/// Plan-phase mismatched-pair detection: when both oauth halves
/// are valid utf-8 PKCS#8 documents but they do not correspond,
/// the plan must surface `OAuthPairMismatch` so the operator sees
/// the refusal before any effect.
#[test]
fn plan_refuses_a_mismatched_oauth_pair_with_both_keys_valid_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	// Mint two independent PKCS#8 ES256 keypairs and pair the
	// first private with the second public. Both halves are
	// valid utf-8 documents, so the mismatch check is the only
	// failure path that fires.
	let (private_a, _public_a) = crate::cli::util::generate_oauth_keypair().expect("mint pair a");
	let (_private_b, public_b) = crate::cli::util::generate_oauth_keypair().expect("mint pair b");
	std::fs::write(keys_dir.join("oauth_signing.key"), &private_a).expect("write private_a");
	std::fs::write(keys_dir.join("oauth_public.key"), public_b.as_bytes()).expect("write public_b");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse a mismatched oauth pair");
	let ApplyError::OAuthPairMismatch = &err else {
		panic!("expected OAuthPairMismatch, got {}", apply_error_name(&err));
	};
}

/// A directory at the storage key path is not a key the run can reuse:
/// the plan must say the key will be written, matching the apply phase,
/// which attempts the write and reports the failure on that path.
#[test]
fn plan_does_not_reuse_a_directory_at_the_storage_key_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let storage = data_dir.join("keys").join("storage.key");
	std::fs::create_dir_all(&storage).expect("blocker dir");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path)).expect("plan");
	let reused = plan.steps.iter().find_map(|step| match step {
		crate::cli::init::plan::PlanStep::Storage { reused, .. } => Some(*reused),
		_ => None,
	});
	assert_eq!(
		reused,
		Some(false),
		"the plan must not report a directory as a reused storage key"
	);
}
