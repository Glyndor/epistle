//! The guard on its own: the policy per address and the limits per window.

use super::*;

fn guard(extra: &str) -> Guard {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"example.com\"]\n{extra}"
	)
	.expect("write config");
	let config = Config::load(file.path()).expect("config loads");
	Guard::from_config(&config, Arc::new(Scopes::from_config(&config)))
}

fn hosted(domain: &str) -> bool {
	domain == "example.org"
}

fn list(addresses: &[&str]) -> Vec<String> {
	addresses.iter().map(|a| (*a).to_string()).collect()
}

const ALICE: (&str, &str) = ("alice", "example.org");

#[test]
fn an_empty_batch_is_never_refused() {
	let guard = guard("[forwarding]\npolicy = \"none\"\naccount_per_min = 1");
	assert_eq!(guard.permitted(ALICE, Vec::new(), hosted), (Vec::new(), 0));
	assert!(guard.charge(ALICE, 0, None, 0));
}

#[test]
fn the_policy_filters_each_address_by_its_own_domain() {
	let guard = guard("[forwarding]\npolicy = \"hosted-only\"");
	let (allowed, refused) = guard.permitted(
		ALICE,
		list(&["a@example.org", "b@other.example", "c@example.org"]),
		hosted,
	);
	assert_eq!(allowed, list(&["a@example.org", "c@example.org"]));
	assert_eq!(refused, 1);
}

#[test]
fn a_scope_policy_applies_to_its_domain_only() {
	let guard = guard("[[antispam_scope]]\ndomain = \"example.com\"\nforward_policy = \"none\"");
	let target = list(&["a@other.example"]);
	assert_eq!(guard.permitted(ALICE, target.clone(), hosted).1, 0);
	assert_eq!(
		guard.permitted(("carol", "example.com"), target, hosted).1,
		1
	);
}

#[test]
fn the_account_window_is_all_or_nothing_and_restarts() {
	let guard = guard("[forwarding]\naccount_per_min = 3");
	assert!(guard.charge(ALICE, 2, None, 1000));
	assert!(!guard.charge(ALICE, 2, None, 1010), "two more do not fit");
	assert!(
		guard.charge(ALICE, 1, None, 1020),
		"the refused batch charged nothing"
	);
	assert!(!guard.charge(ALICE, 1, None, 1030));
	assert!(
		guard.charge(ALICE, 3, None, 1061),
		"the window started over"
	);
	// Another account has a window of its own.
	assert!(guard.charge(("bob", "example.org"), 3, None, 1062));
}

#[test]
fn the_server_window_counts_every_account() {
	let guard = guard("[forwarding]\nserver_per_min = 2");
	assert!(guard.charge(ALICE, 1, None, 1000));
	assert!(guard.charge(("bob", "example.org"), 1, None, 1001));
	assert!(!guard.charge(("carol", "example.org"), 1, None, 1002));
}

#[test]
fn no_limit_anywhere_never_refuses() {
	let guard = guard("");
	assert!(guard.charge(ALICE, 100_000, None, 1000));
}

#[test]
fn the_limit_falls_back_from_scope_to_forwarding_to_submission() {
	let guard = guard(
		"submission_rate_limit_per_min = 7\n[forwarding]\naccount_per_min = 5\n\
		 [[antispam_scope]]\naccount = \"alice\"\nforward_per_min = 2",
	);
	// The scope's 2 for alice, the forwarding 5 for bob.
	assert!(!guard.charge(ALICE, 3, Some(9), 1000));
	assert!(guard.charge(("bob", "example.org"), 5, Some(9), 1000));
	assert!(!guard.charge(("bob", "example.org"), 1, Some(9), 1001));
	// With no forwarding limit the account's own submission limit stands,
	// else the server-wide one.
	let guard = self::guard("submission_rate_limit_per_min = 7");
	assert!(!guard.charge(ALICE, 4, Some(3), 1000));
	assert!(guard.charge(ALICE, 7, None, 1000));
}
