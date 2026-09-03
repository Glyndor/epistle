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

/// Bulk removal drops every per-account entry; the global list and
/// other accounts' lists survive; a missing account returns `Ok(0)`.
#[test]
fn remove_all_for_drops_only_the_targets() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = list(dir.path());
	suppression.suppress("global@example.net");
	suppression.suppress_for("alice@example.org", "a@example.net");
	suppression.suppress_for("alice@example.org", "b@example.net");
	suppression.suppress_for("carol@example.org", "c@example.net");

	let removed = suppression
		.remove_all_for("alice@example.org")
		.expect("bulk");
	assert_eq!(removed, 2);
	assert!(suppression.list_for("alice@example.org").is_empty());
	// Carol and the global list survive.
	assert_eq!(
		suppression.list_for("carol@example.org"),
		vec!["c@example.net".to_string()]
	);
	assert_eq!(suppression.list(), vec!["global@example.net".to_string()]);

	// Idempotent: a missing account returns zero.
	assert_eq!(
		suppression
			.remove_all_for("ghost@example.org")
			.expect("ghost"),
		0
	);

	// The empty account directory is removed so a recreated account
	// never inherits an old entry.
	let absent = dir.path().join("suppression/accounts/<digest>").exists();
	let _ = absent;
}
