//! Tests for reading the subordinate id tables, on literal text only.

use super::{Block, is_free, moved, overlapping};

const DEFAULT: Block = Block {
	start: 100000,
	count: 65536,
};

#[test]
fn the_0_10_1_state_is_an_overlap_with_the_first_user() {
	let table = "tester:100000:65536\nglyndor-epistle:100000:65536\n";
	assert_eq!(overlapping(table), Ok(Some(DEFAULT)));
}

#[test]
fn a_partial_overlap_is_still_an_overlap() {
	let table = "glyndor-epistle:150000:65536\njaroc:100000:65536\n";
	assert_eq!(
		overlapping(table),
		Ok(Some(Block {
			start: 150000,
			count: 65536
		}))
	);
}

#[test]
fn adjacent_ranges_do_not_overlap() {
	let table = "tester:100000:65536\nglyndor-epistle:165536:65536\n";
	assert_eq!(overlapping(table), Ok(None));
	let below = "glyndor-epistle:34464:65536\ntester:100000:65536\n";
	assert_eq!(overlapping(below), Ok(None));
}

#[test]
fn no_entry_for_the_account_is_not_an_overlap() {
	assert_eq!(overlapping("tester:100000:65536\n"), Ok(None));
	assert_eq!(overlapping(""), Ok(None));
}

#[test]
fn comments_and_malformed_lines_are_ignored() {
	let table = "# tester:100000:65536\ntester:x:65536\ntester:100000:0\n\
		glyndor-epistle:100000:65536\n";
	assert_eq!(overlapping(table), Ok(None));
}

#[test]
fn several_ranges_with_one_overlapping_are_refused() {
	let table = "tester:100000:65536\nglyndor-epistle:100000:65536\nglyndor-epistle:400000:10\n";
	let error = overlapping(table).expect_err("two ranges cannot be shifted as one");
	assert!(
		error.contains("2 ranges") && error.contains("glyndor-epistle"),
		"the refusal must say why: {error}"
	);
}

#[test]
fn a_non_default_size_is_reported_as_held() {
	let table = "tester:100000:65536\nglyndor-epistle:160000:1000\n";
	assert_eq!(
		overlapping(table),
		Ok(Some(Block {
			start: 160000,
			count: 1000
		}))
	);
}

#[test]
fn a_free_block_meets_no_entry_including_the_accounts_own() {
	let table = "tester:100000:65536\nglyndor-epistle:100000:65536\n";
	assert!(is_free(
		table,
		Block {
			start: 165536,
			count: 65536
		}
	));
	assert!(!is_free(
		table,
		Block {
			start: 165535,
			count: 65536
		}
	));
	assert!(!is_free(
		"glyndor-epistle:300000:65536\n",
		Block {
			start: 250000,
			count: 65536
		}
	));
}

#[test]
fn a_rewrite_that_moves_only_the_account_passes() {
	let new = Block {
		start: 165536,
		count: 65536,
	};
	let before = "tester:100000:65536\nglyndor-epistle:100000:65536\nother:300000:65536\n";
	let after = "tester:100000:65536\nother:300000:65536\nglyndor-epistle:165536:65536\n";
	assert_eq!(moved(before, after, DEFAULT, new), Ok(()));
}

#[test]
fn a_rewrite_that_touched_another_account_fails() {
	let new = Block {
		start: 165536,
		count: 65536,
	};
	let before = "tester:100000:65536\nglyndor-epistle:100000:65536\n";
	let lost = "glyndor-epistle:165536:65536\n";
	let error = moved(before, lost, DEFAULT, new).expect_err("tester's line vanished");
	assert!(error.contains("tester"), "{error}");
	let kept_old =
		"tester:100000:65536\nglyndor-epistle:100000:65536\nglyndor-epistle:165536:65536\n";
	let error = moved(before, kept_old, DEFAULT, new).expect_err("the old range stayed");
	assert!(error.contains("100000-165535"), "{error}");
	let wrong = "tester:100000:65536\nglyndor-epistle:165537:65536\n";
	assert!(moved(before, wrong, DEFAULT, new).is_err());
}
