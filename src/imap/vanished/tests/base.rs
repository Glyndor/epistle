
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
	record_advancing(dir.path(), &[7]);
	// The uid is logged at some positive mod-sequence.
	assert_eq!(since(dir.path(), 0), vec![7]);
	// An empty set advances nothing.
	record_advancing(dir.path(), &[]);
	assert_eq!(since(dir.path(), 0), vec![7]);
}
