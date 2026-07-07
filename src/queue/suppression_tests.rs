//! Tests for the outbound suppression list.

use super::*;

fn list(dir: &std::path::Path) -> SuppressionList {
	SuppressionList::open(dir).expect("open")
}

#[test]
fn suppress_check_and_remove() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = list(dir.path());
	assert!(!suppression.is_suppressed("bob@example.net"));
	suppression.suppress("bob@example.net");
	assert!(suppression.is_suppressed("bob@example.net"));
	// Case-insensitive.
	assert!(suppression.is_suppressed("BOB@Example.NET"));
	suppression.remove("bob@example.net").expect("remove");
	assert!(!suppression.is_suppressed("bob@example.net"));
	// Removing an absent address is a no-op.
	suppression
		.remove("ghost@example.net")
		.expect("remove absent");
}

#[test]
fn lists_suppressed_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = list(dir.path());
	suppression.suppress("a@example.net");
	suppression.suppress("b@example.net");
	suppression.suppress("a@example.net"); // idempotent
	let mut listed = suppression.list();
	listed.sort();
	assert_eq!(
		listed,
		vec!["a@example.net".to_string(), "b@example.net".to_string()]
	);
}

#[test]
fn per_account_is_isolated_from_global_and_other_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = list(dir.path());
	suppression.suppress_for("alice@example.org", "bob@example.net");

	// Scoped to alice only: not global, not carol's.
	assert!(suppression.is_suppressed_for("alice@example.org", "bob@example.net"));
	assert!(suppression.is_suppressed_for("ALICE@example.org", "BOB@example.net"));
	assert!(!suppression.is_suppressed("bob@example.net"));
	assert!(!suppression.is_suppressed_for("carol@example.org", "bob@example.net"));
	assert!(suppression.list().is_empty());
	assert_eq!(
		suppression.list_for("alice@example.org"),
		vec!["bob@example.net".to_string()]
	);
}

#[test]
fn per_account_remove_is_scoped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = list(dir.path());
	suppression.suppress_for("alice@example.org", "bob@example.net");
	suppression.suppress_for("carol@example.org", "bob@example.net");
	suppression
		.remove_for("alice@example.org", "bob@example.net")
		.expect("remove");
	assert!(!suppression.is_suppressed_for("alice@example.org", "bob@example.net"));
	// Carol's entry is untouched.
	assert!(suppression.is_suppressed_for("carol@example.org", "bob@example.net"));
	// Removing an absent per-account address is a no-op.
	suppression
		.remove_for("alice@example.org", "ghost@example.net")
		.expect("remove absent");
}
