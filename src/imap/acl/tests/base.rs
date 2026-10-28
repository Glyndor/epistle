use super::*;

fn account_with_mailbox(dir: &std::path::Path) {
	// INBOX always exists; create a folder mailbox for the others.
	std::fs::create_dir_all(dir.join("accounts").join("alice").join("new")).expect("inbox");
}

#[test]
fn owner_always_has_all_rights() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	assert_eq!(rights_of(dir.path(), "alice", "INBOX", "alice"), ALL_RIGHTS);
}

#[test]
fn unknown_identifier_has_no_rights() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	assert_eq!(rights_of(dir.path(), "alice", "INBOX", "bob"), "");
}

#[test]
fn set_canonicalises_and_persists() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	// Out-of-order, duplicated input is canonicalised.
	let result = set(dir.path(), "alice", "INBOX", "bob", "srl l").expect("set");
	assert_eq!(result, "lrs");
	assert_eq!(rights_of(dir.path(), "alice", "INBOX", "bob"), "lrs");
}

#[test]
fn plus_and_minus_modify_existing() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	set(dir.path(), "alice", "INBOX", "bob", "lr").expect("set");
	assert_eq!(
		set(dir.path(), "alice", "INBOX", "bob", "+sw").unwrap(),
		"lrsw"
	);
	assert_eq!(
		set(dir.path(), "alice", "INBOX", "bob", "-rw").unwrap(),
		"ls"
	);
}

#[test]
fn removing_all_rights_deletes_entry() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	set(dir.path(), "alice", "INBOX", "bob", "lr").expect("set");
	set(dir.path(), "alice", "INBOX", "bob", "").expect("clear");
	assert!(get(dir.path(), "alice", "INBOX").is_empty());
}

#[test]
fn owner_entry_is_never_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	set(dir.path(), "alice", "INBOX", "alice", "lr").expect("set");
	assert!(get(dir.path(), "alice", "INBOX").is_empty());
}

#[test]
fn delete_removes_only_target() {
	let dir = tempfile::tempdir().expect("tempdir");
	account_with_mailbox(dir.path());
	set(dir.path(), "alice", "INBOX", "bob", "lr").expect("set");
	set(dir.path(), "alice", "INBOX", "carol", "lrs").expect("set");
	delete(dir.path(), "alice", "INBOX", "bob").expect("delete");
	let entries = get(dir.path(), "alice", "INBOX");
	assert_eq!(entries, vec![("carol".to_string(), "lrs".to_string())]);
}

#[test]
fn valid_rights_rejects_unknown_chars() {
	assert!(valid_rights("lrswipkxtea"));
	assert!(!valid_rights("lrZ"));
}
