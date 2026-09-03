//! Tests for the PostgreSQL version floor and the pure function that enforces
//! it.

use super::*;
use std::fs;
use std::path::Path;

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

/// The CI matrix in `.github/workflows/db.yml` must include a
/// `postgres:<N>@sha256:...` image entry where `<N>` is
/// [`MIN_SERVER_VERSION`]. Reading the workflow from disk makes the
/// floor and the CI leg the same fact in two places: a change to one
/// that the other does not track is caught here, not by a post-mortem
/// against the wrong server.
///
/// The needle is `postgres:<N>@sha256:` (with the digest delimiter) so
/// the test cannot false-positive on a comment that just names the
/// major: the only place the image line appears is the matrix.
#[test]
fn the_floor_constant_is_the_one_ci_tests() {
	let workflow =
		fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/db.yml"))
			.expect("read .github/workflows/db.yml");
	let needle = format!("postgres:{MIN_SERVER_VERSION}@sha256:");
	assert!(
		workflow.contains(&needle),
		".github/workflows/db.yml must carry {needle:?} in its matrix so the \
		 floor declared in code and the floor tested in CI cannot drift apart; \
		 the workflow was: {workflow}"
	);
}
