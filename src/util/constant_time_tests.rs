//! Tests for the length-aware constant-time byte comparison.

use super::eq;

#[test]
fn equal_slices_of_equal_length_match() {
	assert!(eq(b"abcdef", b"abcdef"));
	assert!(eq(b"", b""));
	assert!(eq(&[0x00, 0xff, 0x80], &[0x00, 0xff, 0x80]));
}

#[test]
fn different_bytes_in_equal_length_slices_mismatch() {
	assert!(!eq(b"abcdef", b"abcdfg"));
	assert!(!eq(b"abc", b"abd"));
	// A single-bit flip at the start.
	assert!(!eq(&[0x00, 0xff, 0x80], &[0x01, 0xff, 0x80]));
}

#[test]
fn different_length_slices_mismatch_without_scanning() {
	assert!(!eq(b"abc", b"ab"));
	assert!(!eq(b"", b"a"));
	assert!(!eq(b"abcdef", b"abcdefg"));
}
