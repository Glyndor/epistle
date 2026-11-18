use super::*;

#[test]
fn records_and_queries_vanished_uids() {
	let dir = tempfile::tempdir().expect("tempdir");
	// No log yet → nothing vanished.
	assert!(since(dir.path(), 0).is_empty());
	// An empty set is a no-op (no file created).
	record(dir.path(), &[], 5).expect("noop");
	assert!(since(dir.path(), 0).is_empty());

	record(dir.path(), &[1, 2], 10).expect("record");
	record(dir.path(), &[3], 20).expect("record");
	// Everything after modseq 0.
	assert_eq!(since(dir.path(), 0), vec![1, 2, 3]);
	// Only the later expunge after modseq 10.
	assert_eq!(since(dir.path(), 10), vec![3]);
	// Nothing after the highest modseq.
	assert!(since(dir.path(), 20).is_empty());
}

#[test]
fn record_advancing_assigns_a_modseq() {
	let dir = tempfile::tempdir().expect("tempdir");
	record_advancing(dir.path(), dir.path(), &[7]);
	// The uid is logged at some positive mod-sequence.
	assert_eq!(since(dir.path(), 0), vec![7]);
	// An empty set advances nothing.
	record_advancing(dir.path(), dir.path(), &[]);
	assert_eq!(since(dir.path(), 0), vec![7]);
}

#[cfg(unix)]
#[test]
fn record_advancing_does_not_take_its_modseq_from_a_linked_account() {
	let data = tempfile::tempdir().expect("data");
	let outside = tempfile::tempdir().expect("outside");
	std::fs::write(outside.path().join(".modseqctr"), "41").expect("counter");
	std::fs::create_dir_all(data.path().join("accounts")).expect("mkdir");
	let account = data.path().join("accounts").join("alice");
	std::os::unix::fs::symlink(outside.path(), &account).expect("link");
	record_advancing(data.path(), &account, &[9]);
	assert_eq!(since(&account, 1), vec![9], "logged at 2, not at 42");
	assert!(since(&account, 2).is_empty());
}
