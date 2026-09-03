//! Tests for the PostgreSQL version floor and the pure function that enforces
//! it. The `the_floor_constant_is_the_one_ci_tests` test, which guards the
//! code/CI relationship, lives in this file but is added alongside the
//! workflow change that gives it a matrix entry to look for.

use super::*;

/// A `server_version_num` at the floor decodes to the floor and passes.
#[test]
fn major_at_the_floor_passes() {
	match major_meets_floor(140_012, MIN_SERVER_VERSION) {
		Ok(14) => {}
		other => panic!("expected Ok(14), got {other:?}"),
	}
}

/// A `server_version_num` above the floor decodes to its own major and
/// passes.
#[test]
fn major_above_the_floor_passes() {
	match major_meets_floor(180_001, MIN_SERVER_VERSION) {
		Ok(18) => {}
		other => panic!("expected Ok(18), got {other:?}"),
	}
}

/// A `server_version_num` below the floor is refused with the exact
/// `found` and `required` pair the operator will read in the startup error.
#[test]
fn major_below_the_floor_is_refused() {
	match major_meets_floor(130_015, MIN_SERVER_VERSION) {
		Err(DbError::ServerTooOld {
			found: 13,
			required: 14,
		}) => {}
		other => panic!("expected ServerTooOld {{ found: 13, required: 14 }}, got {other:?}"),
	}
}
