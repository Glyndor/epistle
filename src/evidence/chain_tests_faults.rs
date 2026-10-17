//! What a failure to write says about whether the record is on disk.

use super::tests_lines;
use super::*;
use crate::evidence::audit::tests::DAY;
use crate::evidence::test_support::{accepted, at};

fn chain_with_a_record() -> (tempfile::TempDir, Chain) {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("chain");
	chain.append_at(at(DAY, 1), accepted(1)).expect("first");
	(dir, chain)
}

#[test]
fn a_write_that_failed_and_was_cut_off_says_nothing_was_written() {
	let (_dir, chain) = chain_with_a_record();
	chain.inject(FAULT_WRITE);
	let error = chain
		.append_at(at(DAY, 2), accepted(2))
		.expect_err("the write fails");
	assert!(!Unconfirmed::is(&error), "{error}");
	assert_eq!(tests_lines(&chain, Day(DAY)), 1);
}

#[test]
fn a_write_that_failed_and_could_not_be_cut_off_may_be_on_disk() {
	let (_dir, chain) = chain_with_a_record();
	chain.inject(FAULT_WRITE_AND_CUT);
	let error = chain
		.append_at(at(DAY, 2), accepted(2))
		.expect_err("the write fails");
	assert!(Unconfirmed::is(&error), "{error}");
}

#[test]
fn a_sync_that_failed_leaves_the_record_unconfirmed_not_unwritten() {
	let (_dir, chain) = chain_with_a_record();
	chain.inject(FAULT_SYNC);
	let error = chain
		.append_at(at(DAY, 2), accepted(2))
		.expect_err("the sync fails");
	assert!(
		Unconfirmed::is(&error),
		"a failed fdatasync was taken for a record that was not written: {error}"
	);
}
