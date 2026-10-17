//! The operator saying what day it is.
//!
//! A server that was stopped longer than [`super::timeref::START_SLACK_SECS`],
//! or that could not read its log, believes no clock until a timestamp
//! authority vouches for one. Without an authority to ask, the operator can:
//! `epistle evidence clock accept` leaves a request here, and the next tick of
//! the running server takes it if it is fresh and makes the clock it reads
//! the reference. The request is a file and not a signal so that nothing
//! about it needs the server to be reachable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// How old a request may be when the server reads it, in seconds: it names
/// the clock at the time it was made, and a clock that has moved since is
/// not the one the operator looked at. A tick is five minutes apart, and every
/// tick takes the request whether or not it needs it.
pub const FRESH_SECS: u64 = 300;

const FILE: &str = "clock-accepted.json";

#[derive(Serialize, Deserialize)]
struct Request {
	/// The wall clock the operator accepted, epoch seconds.
	time: u64,
}

fn path(evidence_root: &Path) -> PathBuf {
	evidence_root.join(FILE)
}

/// Ask the server to take the wall clock, which reads `wall`, as right.
pub fn request(evidence_root: &Path, wall: u64) -> std::io::Result<()> {
	let bytes = serde_json::to_vec(&Request { time: wall }).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(evidence_root), &bytes)
}

/// Take a request made by someone who looked at a clock reading `wall` (now),
/// if there is a fresh one. The file is removed either way: an old request
/// is not left to be taken at a worse moment.
pub fn take(evidence_root: &Path, wall: u64) -> bool {
	let file = path(evidence_root);
	let Ok(Some(bytes)) = crate::evidence::checkpoint::read_bounded(&file, 4096) else {
		return false;
	};
	let _ = std::fs::remove_file(&file);
	serde_json::from_slice::<Request>(&bytes)
		.is_ok_and(|request| request.time.abs_diff(wall) <= FRESH_SECS)
}

#[cfg(test)]
#[path = "clock_accept_tests.rs"]
mod tests;
