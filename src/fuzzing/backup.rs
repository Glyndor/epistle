//! The backup archive adapter: what an operator hands to `epistle restore`.

use super::common::INPUT_CAP;

/// A backup archive as `epistle restore` reads it from an operator: the
/// bounded gunzip, the tar reader and the check that decides where each
/// member is written, plus a write and read back of what was read.
pub fn backup_tar(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	crate::cli::backup::fuzzing::archive_for_fuzzing(raw);
}
