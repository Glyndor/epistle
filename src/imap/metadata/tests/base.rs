use super::*;

#[test]
fn set_get_roundtrip_and_delete() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice").join("new")).unwrap();
	set(
		dir.path(),
		"alice",
		"INBOX",
		"/private/comment",
		Some("hi there"),
	)
	.expect("set");
	assert_eq!(
		get(dir.path(), "alice", "INBOX", "/private/comment").as_deref(),
		Some("hi there")
	);
	set(dir.path(), "alice", "INBOX", "/private/comment", None).expect("del");
	assert_eq!(get(dir.path(), "alice", "INBOX", "/private/comment"), None);
}

#[test]
fn server_level_annotations() {
	let dir = tempfile::tempdir().expect("tempdir");
	set(dir.path(), "alice", "", "/shared/vendor/x", Some("v")).expect("set");
	assert_eq!(
		get(dir.path(), "alice", "", "/shared/vendor/x").as_deref(),
		Some("v")
	);
}

#[test]
fn values_with_arbitrary_bytes_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice").join("new")).unwrap();
	let value = "line1\nline2 with spaces";
	set(dir.path(), "alice", "INBOX", "/private/x", Some(value)).expect("set");
	assert_eq!(
		get(dir.path(), "alice", "INBOX", "/private/x").as_deref(),
		Some(value)
	);
}

#[test]
fn valid_entry_rules() {
	assert!(valid_entry("/private/comment"));
	assert!(valid_entry("/shared/vendor/a"));
	assert!(!valid_entry("private/comment"));
	assert!(!valid_entry("/bad//entry"));
	assert!(!valid_entry("/has/*/star"));
	assert!(!valid_entry("/"));
}

/// The annotations of the server level belong to the account that wrote them:
/// one account cannot write what another reads, or overwrite it.
#[test]
fn server_annotations_of_two_accounts_are_apart() {
	let dir = tempfile::tempdir().expect("tempdir");
	for account in ["alice", "bob"] {
		std::fs::create_dir_all(dir.path().join("accounts").join(account).join("new")).unwrap();
	}
	set(
		dir.path(),
		"alice",
		"",
		"/shared/comment",
		Some("from alice"),
	)
	.expect("set alice");
	assert_eq!(
		get(dir.path(), "alice", "", "/shared/comment").as_deref(),
		Some("from alice")
	);
	assert_eq!(
		get(dir.path(), "bob", "", "/shared/comment"),
		None,
		"bob does not see alice's"
	);
	set(dir.path(), "bob", "", "/shared/comment", Some("from bob")).expect("set bob");
	assert_eq!(
		get(dir.path(), "alice", "", "/shared/comment").as_deref(),
		Some("from alice")
	);
	assert!(
		!dir.path().join(".metadata-server").exists(),
		"no file shared in the data directory"
	);
}

/// Two writers at the same moment do not lose each other's entry.
#[test]
fn concurrent_sets_keep_every_entry() {
	use std::sync::{Arc, Barrier};
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice").join("new")).unwrap();
	let start = Arc::new(Barrier::new(8));
	let handles: Vec<_> = (0..8)
		.map(|n| {
			let (path, start) = (dir.path().to_path_buf(), start.clone());
			std::thread::spawn(move || {
				start.wait();
				set(&path, "alice", "", &format!("/private/e{n}"), Some("v")).expect("set");
			})
		})
		.collect();
	for handle in handles {
		handle.join().expect("writer");
	}
	for n in 0..8 {
		assert_eq!(
			get(dir.path(), "alice", "", &format!("/private/e{n}")).as_deref(),
			Some("v"),
			"e{n} lost"
		);
	}
}
