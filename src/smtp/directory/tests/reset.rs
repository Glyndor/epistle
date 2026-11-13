//! An account whose credentials were reset after a compromise signs in
//! nowhere, by any proof, until an administrator replaces them, and its
//! refusal looks and costs like a wrong password.

use super::bans::decoy_counters::DecoyCounters;
use super::gate_fixture::*;
use super::{Directory, Proof};
use crate::config::Protocol;
use crate::directory_store::AppPassword;
use crate::test_support::fixtures;

const PROOFS: [Proof; 4] = [
	Proof::Password,
	Proof::Scram,
	Proof::Bearer,
	Proof::Federated,
];

#[test]
fn a_reset_account_is_admitted_by_no_proof_whatever_the_case_of_its_name() {
	let directory = gate_directory();
	for protocol in every_protocol() {
		for proof in PROOFS {
			assert!(!directory.admit_login(RESET, protocol, proof));
			assert!(!directory.admit_login("DAVE", protocol, proof));
			assert!(
				directory.admit_login(OPEN, protocol, proof),
				"the open account is admitted by {proof:?} on {protocol:?}"
			);
		}
	}
	assert!(directory.awaits_credential_reset("Dave"));
	assert!(!directory.awaits_credential_reset(OPEN));
}

/// A directory where both the open and the reset account hold the same app
/// password.
fn with_an_app_password(secret: &str) -> Directory {
	let entry = AppPassword {
		label: "phone".to_string(),
		hash: crate::smtp::auth::tests::base::hash(secret),
		expires_at: None,
		ip_cidr: None,
		save_sent: None,
	};
	gate_directory().with_app_passwords([
		(OPEN.to_string(), entry.clone()),
		(RESET.to_string(), entry),
	])
}

#[test]
fn the_app_passwords_of_a_reset_account_open_nothing() {
	let secret = fixtures::second_password();
	let directory = with_an_app_password(secret);
	// The refusal comes from `admit_login`, which the test above runs on
	// every protocol; one protocol is enough for the app password path.
	assert_eq!(directory.authenticate(RESET, secret, Protocol::Imaps), None);
	assert_eq!(
		directory.authenticate(OPEN, secret, Protocol::Imaps),
		Some(OPEN.to_string()),
		"the same app password opens the open account"
	);
}

/// How many password hashes one refused attempt ran.
fn hashes(directory: Directory, login: &str, password: &str) -> usize {
	let counters = std::sync::Arc::new(DecoyCounters::default());
	let directory = directory.with_decoy_counters(counters.clone());
	assert_eq!(
		directory.authenticate(login, password, Protocol::Imaps),
		None
	);
	counters.hashes()
}

#[test]
fn the_right_password_of_a_reset_account_costs_what_a_wrong_one_costs() {
	let (directory, _, _) = gate_directory_with_app_passwords();
	let wrong = hashes(directory, OPEN, fixtures::wrong_password());
	let (directory, _, _) = gate_directory_with_app_passwords();
	let right = hashes(directory, RESET, fixtures::password());
	assert_eq!(
		right, wrong,
		"the refusal must not say the account is reset"
	);
}
