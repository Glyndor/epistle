
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
