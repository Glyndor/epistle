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
