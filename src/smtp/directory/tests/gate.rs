//! The account rules in [`Directory::admit_login`], the SCRAM planning built
//! on them, and the password path checked against every protocol.

use super::decoy_counters::DecoyCounters;
use super::gate_fixture::*;
use super::{Directory, Proof, ScramRefusal};
use crate::config::Protocol;
use crate::smtp::scram::SCRAM_ITERATIONS;
use crate::test_fixtures as fixtures;

/// Every protocol that authenticates. The match makes a new variant a compile
/// error here, so the parity checks below cannot skip it.
fn every_protocol() -> [Protocol; 9] {
	fn complete(protocol: Protocol) {
		match protocol {
			Protocol::Smtp
			| Protocol::Submission
			| Protocol::Submissions
			| Protocol::Api
			| Protocol::Imaps
			| Protocol::Imap
			| Protocol::Pop3s
			| Protocol::ManageSieve
			| Protocol::WebDav => {}
		}
	}
	let all = [
		Protocol::Smtp,
		Protocol::Submission,
		Protocol::Submissions,
		Protocol::Api,
		Protocol::Imaps,
		Protocol::Imap,
		Protocol::Pop3s,
		Protocol::ManageSieve,
		Protocol::WebDav,
	];
	all.into_iter().for_each(complete);
	all
}

#[test]
fn an_open_account_is_admitted_by_every_proof() {
	let directory = gate_directory();
	for proof in [
		Proof::Password,
		Proof::Scram,
		Proof::Bearer,
		Proof::Federated,
	] {
		assert!(directory.admit_login(OPEN, Protocol::Imaps, proof));
	}
}

#[test]
fn a_disabled_account_is_admitted_by_no_proof_whatever_the_case_of_its_name() {
	let directory = gate_directory();
	for proof in [
		Proof::Password,
		Proof::Scram,
		Proof::Bearer,
		Proof::Federated,
	] {
		assert!(!directory.admit_login(DISABLED, Protocol::Imaps, proof));
		assert!(!directory.admit_login("BOB", Protocol::Imaps, proof));
	}
}

#[test]
fn only_scram_and_a_bare_bearer_are_refused_for_an_account_with_a_second_factor() {
	let directory = gate_directory();
	assert!(!directory.admit_login(TWO_FACTOR, Protocol::Imaps, Proof::Scram));
	assert!(!directory.admit_login(TWO_FACTOR, Protocol::Imaps, Proof::Bearer));
	assert!(directory.admit_login(TWO_FACTOR, Protocol::Imaps, Proof::Password));
	assert!(directory.admit_login(TWO_FACTOR, Protocol::Imaps, Proof::Federated));
}

#[test]
fn the_protocol_allowlist_binds_every_proof() {
	let directory =
		gate_directory().with_allowed_protocols([(OPEN.to_string(), vec![Protocol::Imaps])]);
	for proof in [
		Proof::Password,
		Proof::Scram,
		Proof::Bearer,
		Proof::Federated,
	] {
		assert!(directory.admit_login(OPEN, Protocol::Imaps, proof));
		assert!(!directory.admit_login(OPEN, Protocol::Submission, proof));
	}
}

#[test]
fn the_password_path_refuses_the_same_accounts_on_every_protocol() {
	let directory = gate_directory();
	let off_address = format!("{OFF_DOMAIN_ACCOUNT}@{OFF_DOMAIN}");
	for protocol in every_protocol() {
		for login in [DISABLED, TWO_FACTOR, off_address.as_str()] {
			assert_eq!(
				directory.authenticate(login, fixtures::password(), protocol),
				None,
				"{login} must be refused on {protocol:?}"
			);
		}
		assert_eq!(
			directory.authenticate(OPEN, fixtures::password(), protocol),
			Some(OPEN.to_string())
		);
		// Hashing is slow in a debug build, so take the code when it is used.
		let with_code = format!("{}{}", fixtures::password(), current_totp_code());
		assert_eq!(
			directory.authenticate(TWO_FACTOR, &with_code, protocol),
			Some(TWO_FACTOR.to_string())
		);
	}
}

#[test]
fn app_passwords_off_their_network_or_expired_open_nothing_on_any_protocol() {
	let (directory, expired, elsewhere) = gate_directory_with_app_passwords();
	let peer = Some("203.0.113.9".parse().expect("peer"));
	for protocol in every_protocol() {
		for secret in [expired, elsewhere] {
			assert_eq!(
				directory.authenticate_with_ip(OPEN, secret, peer, protocol),
				None
			);
		}
	}
}

fn directory_without_a_verifier() -> Directory {
	Directory::new(
		["example.org".to_string()],
		[("dana@example.org".to_string(), "dana".to_string())],
	)
	.with_password_hashes([(
		"dana".to_string(),
		crate::smtp::auth::tests::base::hash(fixtures::password()),
	)])
}

#[test]
fn an_open_account_plans_a_real_exchange() {
	let plan = gate_directory().plan_scram(OPEN, None, Protocol::Imaps);
	assert_eq!(plan.account, OPEN);
	assert_eq!(plan.refusal, None);
	assert_eq!(plan.credentials.iterations, 4096);
}

#[test]
fn a_refused_account_plans_a_decoy_counted_against_it() {
	let directory = gate_directory();
	for name in [DISABLED, TWO_FACTOR] {
		let plan = directory.plan_scram(name, None, Protocol::Imaps);
		assert_eq!(
			plan.refusal,
			Some(ScramRefusal::Denied {
				account: Some(name.to_string())
			})
		);
		assert_eq!(plan.credentials.stored_key, [0u8; 32]);
		assert_eq!(plan.credentials.server_key, [0u8; 32]);
		assert_eq!(plan.credentials.iterations, SCRAM_ITERATIONS);
	}
}

#[test]
fn the_decoy_salt_is_stable_per_login_and_not_a_plain_hash_of_it() {
	use ring::digest;
	let directory = gate_directory();
	let salt = |login: &str| {
		directory
			.plan_scram(login, None, Protocol::Imaps)
			.credentials
			.salt
	};
	assert_eq!(salt(DISABLED), salt(DISABLED));
	assert_eq!(salt(DISABLED), salt("BOB"));
	assert_ne!(salt(DISABLED), salt(TWO_FACTOR));
	let unkeyed = digest::digest(&digest::SHA256, DISABLED.as_bytes());
	assert_ne!(
		salt(DISABLED),
		unkeyed.as_ref()[..16].to_vec(),
		"a client must not be able to recompute the decoy salt"
	);
	assert_eq!(salt(DISABLED).len(), 16);
}

#[test]
fn a_login_with_no_verifier_runs_a_decoy_exchange_counted_against_its_account() {
	let plan = directory_without_a_verifier().plan_scram("dana", None, Protocol::Imaps);
	assert_eq!(
		plan.refusal,
		Some(ScramRefusal::Denied {
			account: Some("dana".to_string())
		})
	);
	assert_eq!(plan.credentials.stored_key, [0u8; 32]);
}

#[test]
fn a_login_nobody_holds_runs_the_decoy_exchange_a_refused_account_does() {
	let counters = std::sync::Arc::new(DecoyCounters::default());
	let directory = gate_directory().with_decoy_counters(counters.clone());
	let ghost = directory.plan_scram("ghost", None, Protocol::Imaps);
	assert_eq!(ghost.refusal, Some(ScramRefusal::Denied { account: None }));
	assert_eq!(counters.scram(), 1, "the decoy credentials were built");
	directory.plan_scram(DISABLED, None, Protocol::Imaps);
	assert_eq!(
		counters.scram(),
		2,
		"a refused account builds them the same way"
	);
	directory.plan_scram(OPEN, None, Protocol::Imaps);
	assert_eq!(counters.scram(), 2, "a real exchange builds none");
}

#[test]
fn a_login_without_a_password_still_pays_for_one_hash_check() {
	let counters = std::sync::Arc::new(DecoyCounters::default());
	let directory = gate_directory().with_decoy_counters(counters.clone());
	for (login, password, expected) in [
		("ghost", fixtures::password().to_string(), 1),
		(DISABLED, fixtures::password().to_string(), 2),
		(TWO_FACTOR, fixtures::password().to_string(), 3),
		(OPEN, fixtures::wrong_password().to_string(), 3),
	] {
		assert_eq!(
			directory.authenticate(login, &password, Protocol::Imaps),
			None
		);
		assert_eq!(counters.password(), expected, "after {login}");
	}
}
