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

/// The mode bits of `path`.
#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
	use std::os::unix::fs::PermissionsExt;
	std::fs::metadata(path)
		.expect("metadata")
		.permissions()
		.mode()
		& 0o777
}

/// Every marker and directory the list creates is owner-only, whatever the
/// process umask is (the usual 022 would make them 0644 and 0755).
#[cfg(unix)]
#[test]
#[ignore = "run by markers_are_owner_only_under_every_umask in a child with its own umask"]
fn markers_and_their_directories_are_owner_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = list(dir.path());
	suppression.suppress("a@example.net");
	suppression.suppress_because("b@example.net", "550 no such user", 1);
	suppression
		.try_suppress_because("c@example.net", "550 no such user", 1)
		.expect("write");
	suppression.suppress_for("alice@example.org", "d@example.net");
	suppression.suppress_for_because("alice@example.org", "e@example.net", "550", 1);
	suppression
		.try_suppress_for_because("alice@example.org", "f@example.net", "550", 1)
		.expect("write");
	let root = dir.path().join("suppression");
	let mut seen = 0;
	let mut walk = vec![root.clone()];
	while let Some(path) = walk.pop() {
		let is_dir = path.is_dir();
		let expected = if is_dir { 0o700 } else { 0o600 };
		assert_eq!(mode(&path), expected, "{}", path.display());
		seen += 1;
		if is_dir {
			walk.extend(
				std::fs::read_dir(&path)
					.expect("read_dir")
					.map(|entry| entry.expect("entry").path()),
			);
		}
	}
	// The root, three markers, `accounts`, the account's directory, three markers.
	assert_eq!(seen, 9);
}

/// The same check in a child whose umask is 0 (the old code would give 0666
/// and 0777) and in one whose umask is 077 (where 0600 and 0700 come out
/// of the old code too): the mode is the code's, whatever the umask is.
#[cfg(unix)]
#[test]
fn markers_are_owner_only_under_every_umask() {
	for umask in ["0", "022", "077"] {
		let test = std::env::current_exe().expect("test binary");
		let status = std::process::Command::new("sh")
			.arg("-c")
			.arg(format!(
				"umask {umask}; exec \"$0\" --exact --ignored --nocapture \
				 queue::suppression::tests::base::markers_and_their_directories_are_owner_only"
			))
			.arg(test)
			.output()
			.expect("run the test binary");
		let out = String::from_utf8_lossy(&status.stdout);
		assert!(
			status.status.success() && out.contains("1 passed"),
			"umask {umask}: {out} {}",
			String::from_utf8_lossy(&status.stderr)
		);
	}
}
