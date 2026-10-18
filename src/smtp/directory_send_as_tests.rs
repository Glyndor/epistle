//! `Directory::owns_address` against the shared send-as table.

use super::send_as_fixture::{CASES, directory};
use crate::smtp::address::Address;

#[test]
fn every_case_gets_its_answer() {
	let directory = directory();
	for (account, from, allowed) in CASES {
		let address = Address::parse(from).expect("case addresses parse");
		assert_eq!(
			directory.owns_address(account, &address),
			*allowed,
			"{account} sending as {from}"
		);
	}
}

/// The table has to keep both outcomes and every account, or a rule
/// pushed to "always yes" or "always no" could still pass it.
#[test]
fn the_table_covers_allowed_and_refused_for_each_account() {
	for account in ["alice", "bob", "carol"] {
		for outcome in [true, false] {
			assert!(
				CASES.iter().any(|(a, _, o)| *a == account && *o == outcome),
				"{account} has no case that is {outcome}"
			);
		}
	}
}
